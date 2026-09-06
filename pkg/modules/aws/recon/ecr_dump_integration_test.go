//go:build integration

package recon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRegion = "us-east-2"

// createTestRepo creates an ECR repo and returns its name and a cleanup function.
func createTestRepo(t *testing.T, client *ecr.Client, repoName string) func() {
	t.Helper()
	_, err := client.CreateRepository(context.TODO(), &ecr.CreateRepositoryInput{
		RepositoryName:     &repoName,
		ImageTagMutability: ecrtypes.ImageTagMutabilityMutable,
	})
	require.NoError(t, err, "failed to create ECR repo %s", repoName)

	return func() {
		force := true
		_, err := client.DeleteRepository(context.TODO(), &ecr.DeleteRepositoryInput{
			RepositoryName: &repoName,
			Force:          force,
		})
		if err != nil {
			t.Logf("warning: failed to delete ECR repo %s: %v", repoName, err)
		}
	}
}

// buildTarGzLayer creates a proper tar.gz layer containing a single file.
func buildTarGzLayer(filePath string, content []byte) (v1.Layer, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Name:     filePath,
		Size:     int64(len(content)),
		Mode:     0o644,
		Typeflag: tar.TypeReg,
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}

	return tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}, tarball.WithCompressedCaching)
}

// pushTestImage pushes a minimal :latest image with a planted secret file.
func pushTestImage(t *testing.T, client *ecr.Client, repoName, region string) {
	t.Helper()
	secretContent := []byte(`# Application Configuration
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgres://admin:supersecret@db.internal:5432/app
`)
	pushTaggedTestImage(t, client, repoName, region, "latest", secretContent)
}

// pushTaggedTestImage pushes a minimal single-layer image under one tag, with
// the given file content planted at app/config.txt.
func pushTaggedTestImage(t *testing.T, client *ecr.Client, repoName, region, tag string, secretContent []byte) {
	t.Helper()
	ctx := context.TODO()

	// Get ECR auth.
	authResp, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	require.NoError(t, err)
	require.NotEmpty(t, authResp.AuthorizationData)

	decoded, err := base64.StdEncoding.DecodeString(*authResp.AuthorizationData[0].AuthorizationToken)
	require.NoError(t, err)
	parts := strings.SplitN(string(decoded), ":", 2)
	require.Len(t, parts, 2)

	endpoint := *authResp.AuthorizationData[0].ProxyEndpoint
	accountID := strings.TrimPrefix(endpoint, "https://")
	accountID, _, _ = strings.Cut(accountID, ".")

	auth := authn.FromConfig(authn.AuthConfig{
		Username: parts[0],
		Password: parts[1],
	})

	// Build a proper tar.gz layer with the planted secret.
	layer, err := buildTarGzLayer("app/config.txt", secretContent)
	require.NoError(t, err)

	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	imageURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:%s", accountID, region, repoName, tag)
	ref, err := name.ParseReference(imageURI)
	require.NoError(t, err)

	err = remote.Write(ref, img, remote.WithAuth(auth))
	require.NoError(t, err)

	// Wait briefly for image to be available.
	time.Sleep(2 * time.Second)
}

func TestECRDumpIntegration(t *testing.T) {
	ctx := context.TODO()
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(testRegion))
	require.NoError(t, err)

	client := ecr.NewFromConfig(awsCfg)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%100000)

	// Create repos.
	secretRepoName := fmt.Sprintf("aurelian-test-secret-%s", suffix)
	emptyRepoName := fmt.Sprintf("aurelian-test-empty-%s", suffix)

	cleanupSecret := createTestRepo(t, client, secretRepoName)
	defer cleanupSecret()

	cleanupEmpty := createTestRepo(t, client, emptyRepoName)
	defer cleanupEmpty()

	// Push an image with planted secrets to the secret repo.
	pushTestImage(t, client, secretRepoName, testRegion)

	// Run the ecr-dump module.
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "ecr-dump")
	require.True(t, ok, "ecr-dump module not registered")

	extractDir := t.TempDir()
	cfg := plugin.Config{
		Args: map[string]any{
			"regions":    []string{testRegion},
			"extract":    true,
			"output-dir": extractDir,
		},
		Context: ctx,
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var risks []output.AurelianRisk
	for m := range p2.Range() {
		if r, ok := m.(output.AurelianRisk); ok {
			risks = append(risks, r)
		}
	}
	require.NoError(t, p2.Wait())

	// --- Subtests ---

	t.Run("detects secrets in repo with planted credentials", func(t *testing.T) {
		require.NotEmpty(t, risks, "expected at least one secret risk finding")

		foundForRepo := false
		for _, risk := range risks {
			if strings.Contains(risk.ImpactedResourceID, secretRepoName) {
				foundForRepo = true
				break
			}
		}
		assert.True(t, foundForRepo, "expected a risk referencing %s", secretRepoName)
	})

	t.Run("all risks have aws-secret- prefix", func(t *testing.T) {
		for _, risk := range risks {
			assert.True(t, strings.HasPrefix(risk.Name, "aws-secret-"),
				"risk name %q should start with aws-secret-", risk.Name)
		}
	})

	t.Run("all risks have valid severity", func(t *testing.T) {
		validSeverities := map[output.RiskSeverity]bool{
			output.RiskSeverityLow:      true,
			output.RiskSeverityMedium:   true,
			output.RiskSeverityHigh:     true,
			output.RiskSeverityCritical: true,
		}
		for _, risk := range risks {
			assert.True(t, validSeverities[risk.Severity],
				"unexpected severity %q for risk %s", risk.Severity, risk.Name)
		}
	})

	t.Run("all risks have non-empty context", func(t *testing.T) {
		for _, risk := range risks {
			assert.NotEmpty(t, risk.Context, "risk context should not be empty for %s", risk.ImpactedResourceID)
		}
	})

	t.Run("risks reference ECR resource identifiers", func(t *testing.T) {
		for _, risk := range risks {
			assert.Contains(t, risk.ImpactedResourceID, "ecr",
				"ImpactedResourceID %q should reference ECR", risk.ImpactedResourceID)
		}
	})

	t.Run("extract flag creates layer files on disk", func(t *testing.T) {
		ecrImagesDir := filepath.Join(extractDir, "ecr-images")
		_, err := os.Stat(ecrImagesDir)
		require.NoError(t, err, "ecr-images directory should exist")

		sanitized := sanitizeName(secretRepoName)
		repoDir := filepath.Join(ecrImagesDir, sanitized)
		_, err = os.Stat(repoDir)
		require.NoError(t, err, "repo extract directory should exist at %s", repoDir)

		var extractedFiles []string
		err = filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				extractedFiles = append(extractedFiles, path)
			}
			return nil
		})
		require.NoError(t, err)
		assert.NotEmpty(t, extractedFiles, "expected at least one extracted file")
	})

	t.Run("empty repo produces no findings", func(t *testing.T) {
		for _, risk := range risks {
			assert.False(t, strings.Contains(risk.ImpactedResourceID, emptyRepoName),
				"should not have findings for empty repo %s", emptyRepoName)
		}
	})

	// The modified-since contract from #258: a repository whose newest image was
	// pushed no later than the checkpoint is skipped entirely, so the second run
	// of an unchanged registry must re-report nothing.
	t.Run("modified-since skips a repo whose newest image predates the checkpoint", func(t *testing.T) {
		checkpoint := time.Now().UTC().Format(time.RFC3339Nano)

		cfg := plugin.Config{
			Args: map[string]any{
				"regions":        []string{testRegion},
				"extract":        false,
				"output-dir":     t.TempDir(),
				"modified-since": checkpoint,
			},
			Context: ctx,
		}

		in := pipeline.From(cfg)
		results := pipeline.New[model.AurelianModel]()
		pipeline.Pipe(in, mod.Run, results)

		collected, err := results.Collect()
		require.NoError(t, err, "an incremental run over an unchanged registry must succeed")

		for _, r := range collected {
			risk, ok := r.(output.AurelianRisk)
			if !ok {
				continue
			}
			assert.NotContains(t, risk.ImpactedResourceID, secretRepoName,
				"repo pushed before the checkpoint should have been skipped, got %s", risk.ImpactedResourceID)
		}
	})

	t.Run("images=all scans every image and keeps their findings distinct", func(t *testing.T) {
		// A second image in the same repository. Both carry a secret, and both
		// extract a layer 0, so this also covers the per-image label and extract
		// directory split.
		pushTaggedTestImage(t, client, secretRepoName, testRegion, "v2",
			[]byte("SECOND_AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"))

		extractDir := t.TempDir()
		cfg := plugin.Config{
			Args: map[string]any{
				"regions":    []string{testRegion},
				"extract":    true,
				"output-dir": extractDir,
				"images":     "all",
			},
			Context: ctx,
		}

		in := pipeline.From(cfg)
		results := pipeline.New[model.AurelianModel]()
		pipeline.Pipe(in, mod.Run, results)

		collected, err := results.Collect()
		require.NoError(t, err)
		require.NotEmpty(t, collected)

		// Each image gets its own directory, so layer0/ from one cannot overwrite
		// layer0/ from the other.
		repoDir := filepath.Join(extractDir, "ecr-images", sanitizeName(secretRepoName))
		entries, err := os.ReadDir(repoDir)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(entries), 2,
			"images=all should extract each image into its own directory under %s", repoDir)
	})

	t.Run("images=<tag> scans only the tagged image", func(t *testing.T) {
		extractDir := t.TempDir()
		cfg := plugin.Config{
			Args: map[string]any{
				"regions":    []string{testRegion},
				"extract":    true,
				"output-dir": extractDir,
				"images":     "v2",
			},
			Context: ctx,
		}

		in := pipeline.From(cfg)
		results := pipeline.New[model.AurelianModel]()
		pipeline.Pipe(in, mod.Run, results)

		_, err := results.Collect()
		require.NoError(t, err)

		repoDir := filepath.Join(extractDir, "ecr-images", sanitizeName(secretRepoName))
		entries, err := os.ReadDir(repoDir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "only the requested tag should be pulled")
		assert.Equal(t, sanitizeName("v2"), entries[0].Name())
	})

	t.Run("modified-since still scans a repo pushed after the checkpoint", func(t *testing.T) {
		checkpoint := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano)

		cfg := plugin.Config{
			Args: map[string]any{
				"regions":        []string{testRegion},
				"extract":        false,
				"output-dir":     t.TempDir(),
				"modified-since": checkpoint,
			},
			Context: ctx,
		}

		in := pipeline.From(cfg)
		results := pipeline.New[model.AurelianModel]()
		pipeline.Pipe(in, mod.Run, results)

		collected, err := results.Collect()
		require.NoError(t, err)

		var found bool
		for _, r := range collected {
			if risk, ok := r.(output.AurelianRisk); ok && strings.Contains(risk.ImpactedResourceID, secretRepoName) {
				found = true
				break
			}
		}
		assert.True(t, found, "repo pushed after the checkpoint must still be scanned")
	})
}

func TestECRDumpEmptyRegistry(t *testing.T) {
	ctx := context.TODO()
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(testRegion))
	require.NoError(t, err)

	client := ecr.NewFromConfig(awsCfg)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%100000)
	emptyRepoName := fmt.Sprintf("aurelian-test-onlyempty-%s", suffix)

	cleanup := createTestRepo(t, client, emptyRepoName)
	defer cleanup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "ecr-dump")
	require.True(t, ok, "ecr-dump module not registered")

	cfg := plugin.Config{
		Args: map[string]any{
			"regions":    []string{testRegion},
			"extract":    false,
			"output-dir": t.TempDir(),
		},
		Context: ctx,
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err, "module should not error with empty repos")

	// The empty repo should not produce any findings referencing it.
	for _, r := range results {
		if risk, ok := r.(output.AurelianRisk); ok {
			assert.False(t, strings.Contains(risk.ImpactedResourceID, emptyRepoName),
				"empty repo should produce no findings")
		}
	}
}
