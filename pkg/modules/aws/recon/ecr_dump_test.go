package recon

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
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

func TestECRDumpChooseImages(t *testing.T) {
	checkpoint := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	older := checkpoint.Add(-time.Hour)
	newer := checkpoint.Add(time.Hour)
	newest := checkpoint.Add(2 * time.Hour)

	// Sorted most recently pushed first, as chooseImages requires.
	candidates := []imageCandidate{
		{Tags: []string{"v3"}, Digest: "sha256:cccc", PushedAt: &newest},
		{Tags: []string{"v2", "latest"}, Digest: "sha256:bbbb", PushedAt: &newer},
		{Tags: []string{"v1"}, Digest: "sha256:aaaa", PushedAt: &older},
	}
	const repoURI = "123456789012.dkr.ecr.us-east-2.amazonaws.com/app"

	tests := []struct {
		name        string
		images      string
		incremental bool
		wantURIs    []string
	}{
		{
			name:     "unset selects the most recently pushed image",
			wantURIs: []string{repoURI + ":v3"},
		},
		{
			name:     "newest selects the most recently pushed image",
			images:   imagesNewest,
			wantURIs: []string{repoURI + ":v3"},
		},
		{
			name:     "all selects every image",
			images:   imagesAll,
			wantURIs: []string{repoURI + ":v3", repoURI + ":v2", repoURI + ":v1"},
		},
		{
			name:   "a tag selects only the image carrying it",
			images: "v1",
			// v1 is the oldest image, so this proves tag selection is not
			// restricted to the newest push.
			wantURIs: []string{repoURI + ":v1"},
		},
		{
			name:   "latest means the tag, not the most recent push",
			images: "latest",
			// The newest image is v3, but only v2 carries the "latest" tag, and
			// the reference uses the requested tag rather than the image's first.
			wantURIs: []string{repoURI + ":latest"},
		},
		{
			name:     "an unmatched tag selects nothing",
			images:   "nope",
			wantURIs: nil,
		},
		{
			name:        "all skips images pushed no later than the checkpoint",
			images:      imagesAll,
			incremental: true,
			wantURIs:    []string{repoURI + ":v3", repoURI + ":v2"},
		},
		{
			name:        "a tag on an unchanged image is skipped",
			images:      "v1",
			incremental: true,
			wantURIs:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := &ecrDumpRun{
				images:        tt.images,
				incremental:   tt.incremental,
				modifiedSince: checkpoint,
			}
			base := ecrImage{RepoName: "app", Region: "us-east-2", AccountID: "123456789012"}

			selected := run.chooseImages(base, repoURI, candidates)

			var got []string
			for _, img := range selected {
				got = append(got, img.ImageURI)
				assert.Equal(t, "app", img.RepoName, "repository identity must carry over")
			}
			assert.Equal(t, tt.wantURIs, got)
		})
	}
}

func TestECRDumpChooseImagesEmptyRepository(t *testing.T) {
	run := &ecrDumpRun{}
	assert.Empty(t, run.chooseImages(ecrImage{RepoName: "empty"}, "uri", nil))
}

func TestImageReference(t *testing.T) {
	const repoURI = "123456789012.dkr.ecr.us-east-2.amazonaws.com/app"

	t.Run("prefers the requested tag over the image's first", func(t *testing.T) {
		tag, uri := imageReference(repoURI, imageCandidate{Tags: []string{"latest", "v2"}}, "v2")
		assert.Equal(t, "v2", tag)
		assert.Equal(t, repoURI+":v2", uri)
	})

	t.Run("falls back to the first tag", func(t *testing.T) {
		tag, uri := imageReference(repoURI, imageCandidate{Tags: []string{"latest", "v2"}}, "")
		assert.Equal(t, "latest", tag)
		assert.Equal(t, repoURI+":latest", uri)
	})

	t.Run("references an untagged image by digest", func(t *testing.T) {
		tag, uri := imageReference(repoURI, imageCandidate{Digest: "sha256:abcd"}, "")
		assert.Equal(t, "sha256:abcd", tag)
		assert.Equal(t, repoURI+"@sha256:abcd", uri)
	})

	t.Run("an image with neither tag nor digest is unpullable", func(t *testing.T) {
		tag, uri := imageReference(repoURI, imageCandidate{}, "")
		assert.Empty(t, tag)
		assert.Empty(t, uri)
	})
}

func TestECRImageRef(t *testing.T) {
	// The ref prefixes scan labels and extract paths, so two images of one
	// repository must not produce the same value.
	v1 := ecrImage{RepoName: "app", Tag: "v1"}
	v2 := ecrImage{RepoName: "app", Tag: "v2"}
	assert.Equal(t, "app:v1", v1.ref())
	assert.NotEqual(t, v1.ref(), v2.ref())
	assert.NotEqual(t, sanitizeName(v1.Tag), sanitizeName(v2.Tag),
		"per-image extract directories must differ or layer0/ collides")

	// A repository with no resolvable tag still yields a usable ref.
	assert.Equal(t, "app", ecrImage{RepoName: "app"}.ref())
}

func TestExtractLayerLabelsAreImageScoped(t *testing.T) {
	// Two images of one repository both produce a layer 0 containing the same
	// path. Without the image in the label the two findings are indistinguishable.
	tarFor := func(t *testing.T) io.Reader {
		t.Helper()
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		content := []byte("AWS_SECRET_ACCESS_KEY=placeholder\n")
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     "app/config.env",
			Size:     int64(len(content)),
			Mode:     0o644,
			Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write(content)
		require.NoError(t, err)
		require.NoError(t, tw.Close())
		return &buf
	}

	target := layerScanTarget{
		arn:          "arn:aws:ecr:us-east-2:123456789012:repository/app",
		resourceType: "AWS::ECR::Repository",
		region:       "us-east-2",
		accountID:    "123456789012",
	}

	targetV1 := target
	targetV1.imageRef = ecrImage{RepoName: "app", Tag: "v1"}.ref()
	targetV2 := target
	targetV2.imageRef = ecrImage{RepoName: "app", Tag: "v2"}.ref()

	v1, err := extractLayer(tarFor(t), targetV1, t.TempDir(), false, 0)
	require.NoError(t, err)
	require.Len(t, v1, 1)

	v2, err := extractLayer(tarFor(t), targetV2, t.TempDir(), false, 0)
	require.NoError(t, err)
	require.Len(t, v2, 1)

	assert.Equal(t, "app:v1:layer0/app/config.env", v1[0].Label)
	assert.Equal(t, "app:v2:layer0/app/config.env", v2[0].Label)
	assert.NotEqual(t, v1[0].Label, v2[0].Label)

	// Everything else about the two inputs is identical: same repository, so the
	// same ARN, and both are attributed to AWS.
	assert.Equal(t, target.arn, v1[0].ResourceID)
	assert.Equal(t, "aws", v1[0].Platform)
	assert.Equal(t, target.resourceType, v1[0].ResourceType)
}

func TestExtractLayerWritesUnderTheGivenDirectory(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("token=placeholder\n")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "etc/app.conf",
		Size:     int64(len(content)),
		Mode:     0o644,
		Typeflag: tar.TypeReg,
	}))
	_, err := tw.Write(content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	dir := t.TempDir()
	inputs, err := extractLayer(&buf, layerScanTarget{imageRef: "app:v1"}, dir, true, 0)
	require.NoError(t, err)
	require.Len(t, inputs, 1)

	written := filepath.Join(dir, "layer0", "etc", "app.conf")
	got, err := os.ReadFile(written)
	require.NoError(t, err, "layer file should be written beneath the per-image directory")
	assert.Equal(t, content, got)
}
