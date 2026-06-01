//go:build integration

package enumeration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSkipResilience_RestrictedRole provisions a restricted IAM role via
// Terraform and enumerates multiple resource types that produce different
// error classes:
//
//	S3       — fully allowed     → happy path, resources returned
//	IAM      — fully allowed     → happy path, global resources returned
//	Amplify  — fully denied      → AccessDeniedException, skipped
//	SSM      — fully denied      → AccessDeniedException, skipped
//	EC2 AMI  — DescribeImages OK, DescribeImageAttribute denied → partial
//
// The test verifies:
//   - allowed services return results
//   - denied services are skipped without aborting the pipeline
//   - the SkipReport captures each denial with the correct error code
//   - the summary and detail file are written and consistent
func TestSkipResilience_RestrictedRole(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	require.NotEmpty(t, restrictedRoleARN, "restricted_role_arn must be in Terraform outputs")

	// Write a temporary AWS profile that assumes the restricted role.
	profileDir := t.TempDir()
	profileName := "aurelian-test-restricted"
	sourceProfile := os.Getenv("AWS_PROFILE")
	if sourceProfile == "" {
		sourceProfile = "default"
	}

	configContent := "[profile " + profileName + "]\n" +
		"role_arn = " + restrictedRoleARN + "\n" +
		"source_profile = " + sourceProfile + "\n" +
		"region = us-east-1\n"

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	origConfig, _ := os.ReadFile(filepath.Join(homeDir, ".aws", "config"))
	origCreds, _ := os.ReadFile(filepath.Join(homeDir, ".aws", "credentials"))

	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "config"), append(origConfig, []byte("\n"+configContent)...), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "credentials"), origCreds, 0o600))

	// Sanity check: verify assume-role works before running enumerator.
	ctx := context.Background()
	baseCfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(sourceProfile),
		config.WithRegion("us-east-1"),
	)
	require.NoError(t, err)
	stsClient := sts.NewFromConfig(baseCfg)
	_, err = stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         &restrictedRoleARN,
		RoleSessionName: strPtr("aurelian-skip-test"),
	})
	require.NoError(t, err, "must be able to assume the restricted role — check Terraform trust policy")

	outputDir := t.TempDir()
	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  outputDir,
		},
		Regions:     []string{"us-east-1"},
		Concurrency: 2,
	})
	defer enumerator.Close()

	// --- Happy path: S3 (fully allowed) ---
	t.Run("S3_allowed", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::S3::Bucket", out)
		})
		require.NoError(t, err, "S3 should not error")
		assert.NotEmpty(t, results, "S3 should return buckets")
		t.Logf("S3: %d buckets", len(results))
	})

	// --- Happy path: IAM (fully allowed, global) ---
	t.Run("IAM_allowed", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::IAM::Role", out)
		})
		require.NoError(t, err, "IAM should not error")
		assert.NotEmpty(t, results, "IAM should return roles")
		t.Logf("IAM roles: %d", len(results))
	})

	// --- Error path: Amplify (fully denied) ---
	t.Run("Amplify_denied", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::Amplify::App", out)
		})
		require.NoError(t, err, "Amplify denial should be skipped, not returned as error")
		assert.Empty(t, results, "denied Amplify should produce no resources")
	})

	// --- Error path: SSM (fully denied) ---
	t.Run("SSM_denied", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::SSM::Document", out)
		})
		require.NoError(t, err, "SSM denial should be skipped, not returned as error")
		assert.Empty(t, results, "denied SSM should produce no resources")
	})

	// --- Partial error path: EC2 images ---
	// DescribeImages is allowed but DescribeImageAttribute is denied.
	// The enumerator should list images but fail on enrichment (per-image
	// buildResource calls DescribeImageAttribute). The enrichment failure
	// is handled as a per-item warn, not a skip. If there are no AMIs owned
	// by the account, this is effectively a no-op.
	t.Run("EC2_partial", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::EC2::Image", out)
		})
		// Should not abort regardless of whether images exist.
		require.NoError(t, err, "EC2 partial denial should not abort")
		t.Logf("EC2 images: %d (may be 0 if no self-owned AMIs)", len(results))
	})

	// --- Critical: mixed pipeline — denied types must not cause loss of allowed types ---
	// This simulates the real list-all pattern: multiple resource types fed
	// through pipeline.Pipe. If one type is denied, the others must still
	// produce their full results.
	t.Run("MixedPipeline_no_resource_loss", func(t *testing.T) {
		// Feed a mix of allowed and denied types through a single pipeline.
		types := pipeline.From(
			"AWS::S3::Bucket",      // allowed
			"AWS::Amplify::App",    // denied
			"AWS::IAM::Role",       // allowed
			"AWS::SSM::Document",   // denied
		)
		listed := pipeline.New[output.AWSResource]()
		pipeline.Pipe(types, enumerator.List, listed)

		results, err := listed.Collect()
		require.NoError(t, err, "pipeline must not fail when some types are denied")

		// Collect by resource type.
		byType := make(map[string]int)
		for _, r := range results {
			byType[r.ResourceType]++
		}
		t.Logf("MixedPipeline results: %v", byType)

		// S3 and IAM must have produced resources.
		assert.Greater(t, byType["AWS::S3::Bucket"], 0,
			"S3 buckets must survive alongside denied types")
		assert.Greater(t, byType["AWS::IAM::Role"], 0,
			"IAM roles must survive alongside denied types")

		// Denied types must produce zero resources.
		assert.Equal(t, 0, byType["AWS::Amplify::App"],
			"denied Amplify should produce no resources")
		assert.Equal(t, 0, byType["AWS::SSM::Document"],
			"denied SSM should produce no resources")
	})

	// --- Verify SkipReport captured all denials ---
	t.Run("SkipReport_completeness", func(t *testing.T) {
		snap := enumerator.Skipped.Snapshot()
		require.NotEmpty(t, snap, "SkipReport should have recorded denials")

		// Collect all services that appear in the skip report.
		skippedServices := make(map[string]bool)
		for _, op := range snap {
			skippedServices[op.Service] = true
			// Every skip should have an AccessDenied-family code.
			assert.Contains(t, op.ErrorCode, "AccessDenied",
				"skip for %s %s should have AccessDenied code, got %s", op.Service, op.Operation, op.ErrorCode)
		}

		// Amplify and SSM must appear (they're fully denied).
		// They may appear as the short service name (inner loop) or as the
		// CloudControl type string (dispatcher safety net).
		amplifyFound := skippedServices["amplify"] || skippedServices["AWS::Amplify::App"]
		ssmFound := skippedServices["ssm"] || skippedServices["AWS::SSM::Document"]
		assert.True(t, amplifyFound, "SkipReport must contain Amplify denial; services found: %v", skippedServices)
		assert.True(t, ssmFound, "SkipReport must contain SSM denial; services found: %v", skippedServices)

		t.Logf("SkipReport: %d entries", len(snap))
		for _, op := range snap {
			t.Logf("  %s %s region=%s code=%s", op.Service, op.Operation, op.Region, op.ErrorCode)
		}
	})

	// --- Verify summary and detail file ---
	t.Run("Summary_and_detail_file", func(t *testing.T) {
		summary := enumerator.Skipped.Summary()
		assert.NotEmpty(t, summary)
		assert.Contains(t, summary, "AccessDenied")
		t.Logf("Summary:\n%s", summary)

		// Force write the detail file (Close hasn't fired yet because of defer).
		require.NoError(t, enumerator.Skipped.WriteDetailFile(outputDir))
		detailPath := filepath.Join(outputDir, "enumeration-skips.json")
		info, err := os.Stat(detailPath)
		require.NoError(t, err, "detail file should exist")
		assert.True(t, info.Size() > 0, "detail file should not be empty")
		t.Logf("Detail file: %s (%d bytes)", detailPath, info.Size())
	})
}

// stscreds is imported to ensure the SDK can resolve assume-role profiles.
var _ = stscreds.NewAssumeRoleProvider

func strPtr(s string) *string { return &s }
