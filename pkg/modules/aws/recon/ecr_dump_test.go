package recon

import (
	"testing"

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
