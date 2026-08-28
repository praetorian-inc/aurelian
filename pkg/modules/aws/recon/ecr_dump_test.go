package recon

import (
	"testing"
	"time"

	cclist "github.com/praetorian-inc/aurelian/pkg/aws/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECRDumpModuleRegistration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "ecr-dump")
	require.True(t, ok, "ecr-dump module should be registered")
	require.NotNil(t, mod)
}

func TestECRDumpModuleMetadata(t *testing.T) {
	m := &AWSECRDumpModule{}
	assert.Equal(t, "ecr-dump", m.ID())
	assert.Equal(t, "AWS ECR Dump", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.Contains(t, m.Description(), "ECR")
	assert.Contains(t, m.Description(), "Titus")

	refs := m.References()
	require.Len(t, refs, 2)

	types := m.SupportedResourceTypes()
	assert.Contains(t, types, "AWS::ECR::Repository")
	assert.Contains(t, types, "AWS::ECR::PublicRepository")
}

func TestECRDumpModuleParameters(t *testing.T) {
	m := &AWSECRDumpModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["regions"], "should have regions param")
	assert.True(t, paramNames["extract"], "should have extract param")
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"my-repo", "my-repo"},
		{"org/my-repo", "org_my-repo"},
		{"my.repo:latest", "my_repo_latest"},
		{"a/b/c.d:e", "a_b_c_d_e"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, sanitizeName(tt.input))
	}
}

func TestIsBinary(t *testing.T) {
	assert.False(t, isBinary([]byte("hello world")))
	assert.False(t, isBinary([]byte("#!/bin/bash\necho hi")))
	assert.True(t, isBinary([]byte{0x89, 0x50, 0x4e, 0x47, 0x00})) // PNG header with null
	assert.True(t, isBinary([]byte("ELF\x00binary")))
	assert.False(t, isBinary([]byte{}))
}

func TestEmitResultsBuildsSecretRisks(t *testing.T) {
	result := secrets.SecretScanResult{
		ResourceRef:  "arn:aws:ecr:us-east-2:123456789012:repository/my-repo",
		ResourceType: "AWS::ECR::Repository",
		Region:       "us-east-2",
		AccountID:    "123456789012",
		Platform:     "aws",
		Label:        "my-repo:layer0/app/config.txt",
		Match: &types.Match{
			RuleID:    "np.aws.1",
			RuleName:  "AWS API Key",
			FindingID: "abcdef1234567890",
			Snippet: types.Snippet{
				Before:   []byte("AWS_ACCESS_KEY_ID="),
				Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
				After:    []byte("\n"),
			},
		},
	}

	out := pipeline.New[model.AurelianModel]()
	var findings []scanFinding
	go func() {
		defer out.Close()
		findings = emitResults([]secrets.SecretScanResult{result}, out)
	}()

	emitted, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, emitted, 1, "one scan result should emit one risk")

	risk, ok := emitted[0].(output.AurelianRisk)
	require.True(t, ok, "emitted model should be an AurelianRisk")
	assert.Equal(t, "aws-secret-aws", risk.Name)
	assert.Equal(t, "arn:aws:ecr:us-east-2:123456789012:repository/my-repo:abcdef12", risk.ImpactedResourceID)
	assert.Equal(t, "abcdef1234567890", risk.DeduplicationID)
	assert.NotEmpty(t, risk.Context, "risk must carry proof context")

	require.Len(t, findings, 1, "one scan result should produce one console finding")
	assert.Equal(t, "AWS API Key", findings[0].RuleName)
	assert.Equal(t, "my-repo:layer0/app/config.txt", findings[0].Label)
}

func TestECRDumpSkipUnchanged(t *testing.T) {
	checkpoint := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	before := checkpoint.Add(-time.Hour)
	after := checkpoint.Add(time.Hour)

	tests := []struct {
		name        string
		incremental bool
		pushedAt    *time.Time
		want        bool
	}{
		{"pushed before checkpoint is skipped", true, &before, true},
		{"pushed exactly at checkpoint is skipped", true, &checkpoint, true},
		{"pushed after checkpoint is scanned", true, &after, false},
		{"missing push time fails open", true, nil, false},
		{"non-incremental run never skips", false, &before, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := &ecrDumpRun{modifiedSince: checkpoint, incremental: tt.incremental}
			assert.Equal(t, tt.want, run.skipUnchanged(tt.pushedAt))
		})
	}
}

func TestECRDumpProblemFailsClosedWhenIncremental(t *testing.T) {
	run := &ecrDumpRun{incremental: true}
	err := run.problem("failed to list repos in %s: %v", "us-east-2", assert.AnError)
	require.Error(t, err, "an incremental run must not report success after skipping content")
	assert.Contains(t, err.Error(), "us-east-2")
}

func TestECRDumpProblemContinuesWhenBestEffort(t *testing.T) {
	// A zero-value Config has no Logger; Warn is a no-op. What matters is that
	// no error escapes, which is what lets the run continue to the next repo.
	run := &ecrDumpRun{cfg: plugin.Config{}}
	assert.NoError(t, run.problem("failed to list repos: %v", assert.AnError))
}

func TestECRDumpModifiedSinceParameter(t *testing.T) {
	m := &AWSECRDumpModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	var found bool
	for _, p := range params {
		if p.Name == "modified-since" {
			found = true
		}
	}
	assert.True(t, found, "ecr-dump should expose --modified-since like find-secrets does")
}

func TestECRDumpRejectsInvalidModifiedSince(t *testing.T) {
	m := &AWSECRDumpModule{}
	m.ModifiedSince = "not-a-timestamp"

	// Run rejects the timestamp before it starts the scanner or reaches AWS, so
	// nothing is ever sent to the output pipeline.
	err := m.Run(plugin.Config{}, pipeline.New[model.AurelianModel]())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid modified-since timestamp")
}

func TestECRDumpProcessRepositorySkipsWithoutTouchingAWS(t *testing.T) {
	m := &AWSECRDumpModule{}
	checkpoint := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	pushedBefore := checkpoint.Add(-time.Hour)

	tests := []struct {
		name string
		run  *ecrDumpRun
		repo output.AWSResource
	}{
		{
			name: "unchanged repository is skipped before the pull",
			run:  &ecrDumpRun{modifiedSince: checkpoint, incremental: true},
			repo: output.AWSResource{
				ResourceID:   "app",
				Region:       "us-east-2",
				LastModified: &pushedBefore,
				Properties: map[string]any{
					cclist.ECRPropImageURI: "123456789012.dkr.ecr.us-east-2.amazonaws.com/app:v1",
					cclist.ECRPropImageTag: "v1",
				},
			},
		},
		{
			name: "repository with no enumerated image reference is skipped",
			run:  &ecrDumpRun{},
			repo: output.AWSResource{
				ResourceID: "empty",
				Region:     "us-east-2",
				Properties: map[string]any{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A nil auth cache would panic if the skip fell through to run.auth,
			// which is the point: these paths must not reach AWS at all.
			findings, err := m.processRepository(tt.run, tt.repo)
			require.NoError(t, err)
			assert.Empty(t, findings)
		})
	}
}
