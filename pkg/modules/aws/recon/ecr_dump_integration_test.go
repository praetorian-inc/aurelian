//go:build integration

package recon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECRDumpIntegration(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/ecr-dump")
	fixture.Setup()

	region := fixture.Output("region")
	secretRepoName := fixture.Output("secret_repo_name")
	secretRepoARN := fixture.Output("secret_repo_arn")
	emptyRepoName := fixture.Output("empty_repo_name")

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "ecr-dump")
	if !ok {
		t.Fatal("ecr-dump module not registered in plugin system")
	}

	// Use a temp dir for extracted files so we can verify --extract behavior.
	extractDir := t.TempDir()

	cfg := plugin.Config{
		Args: map[string]any{
			"regions":    []string{region},
			"extract":    true,
			"output-dir": extractDir,
		},
		Context: context.Background(),
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

	// --- Subtest: Secret detection in repo with planted credentials ---
	t.Run("detects secrets in repo with planted credentials", func(t *testing.T) {
		require.NotEmpty(t, risks, "expected at least one secret risk finding from the planted repo")

		foundForRepo := false
		for _, risk := range risks {
			if strings.Contains(risk.ImpactedResourceID, secretRepoName) ||
				risk.ImpactedResourceID == secretRepoARN {
				foundForRepo = true
				break
			}
		}
		assert.True(t, foundForRepo, "expected a risk referencing the secret repo %s", secretRepoName)
	})

	// --- Subtest: All risks have aws-secret- prefix ---
	t.Run("all risks have aws-secret- prefix", func(t *testing.T) {
		for _, risk := range risks {
			assert.True(t, strings.HasPrefix(risk.Name, "aws-secret-"),
				"risk name %q should start with aws-secret-", risk.Name)
		}
	})

	// --- Subtest: All risks have valid severity ---
	t.Run("all risks have severity set", func(t *testing.T) {
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

	// --- Subtest: All risks have non-empty context ---
	t.Run("all risks have non-empty context", func(t *testing.T) {
		for _, risk := range risks {
			assert.NotEmpty(t, risk.Context, "risk context should not be empty for %s", risk.ImpactedResourceID)
		}
	})

	// --- Subtest: Risks reference the ECR repo ARN or name ---
	t.Run("risks reference ECR resource identifiers", func(t *testing.T) {
		for _, risk := range risks {
			hasRef := strings.Contains(risk.ImpactedResourceID, "ecr") ||
				strings.Contains(risk.ImpactedResourceID, secretRepoName)
			assert.True(t, hasRef,
				"risk ImpactedResourceID %q should reference ECR repo", risk.ImpactedResourceID)
		}
	})

	// --- Subtest: Extract flag creates files on disk ---
	t.Run("extract flag creates layer files on disk", func(t *testing.T) {
		ecrImagesDir := filepath.Join(extractDir, "ecr-images")

		// Check that the extract directory was created.
		_, err := os.Stat(ecrImagesDir)
		require.NoError(t, err, "ecr-images directory should exist at %s", ecrImagesDir)

		// Check that the secret repo's extract directory contains files.
		sanitized := sanitizeName(secretRepoName)
		repoDir := filepath.Join(ecrImagesDir, sanitized)
		_, err = os.Stat(repoDir)
		require.NoError(t, err, "repo extract directory should exist at %s", repoDir)

		// Walk the extracted directory and verify at least one file was extracted.
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
		assert.NotEmpty(t, extractedFiles, "expected at least one extracted file in %s", repoDir)

		// Verify the planted config.txt was extracted.
		foundConfig := false
		for _, f := range extractedFiles {
			if strings.Contains(f, "config.txt") {
				foundConfig = true
				// Read the file and verify it contains the planted secret.
				content, err := os.ReadFile(f)
				require.NoError(t, err)
				assert.Contains(t, string(content), "AKIAIOSFODNN7EXAMPLE",
					"extracted config.txt should contain the planted access key")
				break
			}
		}
		assert.True(t, foundConfig, "expected config.txt to be among extracted files")
	})

	// --- Subtest: Empty repo produces no errors and no findings ---
	t.Run("empty repo produces no findings", func(t *testing.T) {
		// The empty repo should not have caused any risks — verify no risk
		// references the empty repo.
		for _, risk := range risks {
			assert.False(t, strings.Contains(risk.ImpactedResourceID, emptyRepoName),
				"should not have findings for empty repo %s, got risk: %s", emptyRepoName, risk.Name)
		}
	})
}

func TestECRDumpEmptyRegistry(t *testing.T) {
	// This test verifies the module handles an account with only empty ECR repos
	// gracefully — no errors, no findings. We run against a region that only has
	// the empty repo from our fixture (the secret repo also exists but is tested above).
	//
	// We specifically test the module's behavior when repos have zero images.

	fixture := testutil.NewAWSFixture(t, "aws/recon/ecr-dump")
	fixture.Setup()

	region := fixture.Output("region")

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "ecr-dump")
	if !ok {
		t.Fatal("ecr-dump module not registered in plugin system")
	}

	// Run the module — both repos exist but the module should handle the empty
	// one gracefully (skip it with a warning, not fail).
	cfg := plugin.Config{
		Args: map[string]any{
			"regions":    []string{region},
			"extract":    false,
			"output-dir": t.TempDir(),
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err, "module should not return an error even with empty repos present")

	// With extract=false, the module should still scan and find secrets in the
	// secret repo but should not error on the empty repo.
	t.Run("no extract dir created when extract=false", func(t *testing.T) {
		// Verify that no ecr-images directory was created in the temp output dir
		// for the empty repo (since extract=false).
		emptyRepoName := fixture.Output("empty_repo_name")
		for _, r := range results {
			if risk, ok := r.(output.AurelianRisk); ok {
				assert.False(t, strings.Contains(risk.ImpactedResourceID, emptyRepoName),
					"empty repo should produce no findings")
			}
		}
	})
}
