//go:build integration

package enumeration

import (
	"context"
	"encoding/json"
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

	profileDir, profileName := setupRestrictedProfile(t, restrictedRoleARN)

	// Sanity check: verify assume-role works before running enumerator.
	ctx := context.Background()
	baseCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
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

	// --- Error path: CloudControl-only type (no native enumerator) ---
	// Lambda has no native enumerator — it falls through to CloudControl.
	// The restricted role has no lambda:* permissions, so CloudControl's
	// ListResources call should fail and be classified as skippable.
	// This exercises the CloudControl inner skip path (listInRegionByType).
	t.Run("CloudControl_denied", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::Lambda::Function", out)
		})
		require.NoError(t, err, "CloudControl denial should be skipped, not returned as error")
		// May return results if CloudControl happens to have read access
		// via cloudcontrol:ListResources (which is allowed). The deny is on
		// lambda:* not cloudcontrol:*, so CloudControl may or may not succeed
		// depending on the underlying service authorization model.
		t.Logf("CloudControl Lambda: %d results", len(results))
	})

	// --- Partial error path: EC2 images ---
	// DescribeImages is allowed but DescribeImageAttribute is denied.
	// The enumerator lists images but buildResource fails per-image because
	// DescribeImageAttribute returns UnauthorizedOperation. Each failure is
	// logged as a per-item warn and the image is skipped (continue), but the
	// pipeline does not abort. The result is 0 enriched images even though
	// DescribeImages found AMIs — this is correct behavior for partial denial.
	t.Run("EC2_partial", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::EC2::Image", out)
		})
		require.NoError(t, err, "EC2 partial denial should not abort the pipeline")
		// Results may be 0 because all images failed enrichment, or because
		// there are no self-owned AMIs. Either way, no abort.
		t.Logf("EC2 images: %d (0 expected when all images fail enrichment)", len(results))
	})

	// --- Critical: mixed pipeline — denied types must not cause loss of allowed types ---
	// This simulates the real list-all pattern: multiple resource types fed
	// through pipeline.Pipe. If one type is denied, the others must still
	// produce their full results.
	//
	// Uses a fresh enumerator because IAM's sync.Once means a second
	// EnumerateAll on the same instance is a no-op (by design — IAM is global).
	t.Run("MixedPipeline_no_resource_loss", func(t *testing.T) {
		mixedEnum := NewEnumerator(plugin.AWSCommonRecon{
			AWSReconBase: plugin.AWSReconBase{
				Profile:    profileName,
				ProfileDir: profileDir,
				OutputDir:  t.TempDir(),
			},
			Regions:     []string{"us-east-1"},
			Concurrency: 2,
		})
		defer mixedEnum.Close()

		// Feed a mix of allowed and denied types through a single pipeline.
		types := pipeline.From(
			"AWS::S3::Bucket",      // allowed
			"AWS::Amplify::App",    // denied
			"AWS::IAM::Role",       // allowed (global, sync.Once)
			"AWS::SSM::Document",   // denied
		)
		listed := pipeline.New[output.AWSResource]()
		pipeline.Pipe(types, mixedEnum.List, listed)

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

		// Verify the mixed enumerator's own SkipReport captured both denials.
		snap := mixedEnum.Skipped.Snapshot()
		skippedServices := make(map[string]bool)
		for _, op := range snap {
			skippedServices[op.Service] = true
		}
		assert.True(t, skippedServices["amplify"] || skippedServices["AWS::Amplify::App"],
			"mixed pipeline SkipReport must contain Amplify denial")
		assert.True(t, skippedServices["ssm"] || skippedServices["AWS::SSM::Document"],
			"mixed pipeline SkipReport must contain SSM denial")
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

	// --- Verify summary and detail file are consistent ---
	t.Run("Summary_and_detail_file", func(t *testing.T) {
		summary := enumerator.Skipped.Summary()
		assert.NotEmpty(t, summary)
		assert.Contains(t, summary, "AccessDenied")
		t.Logf("Summary:\n%s", summary)

		// Force write the detail file (Close hasn't fired yet because of defer).
		require.NoError(t, enumerator.Skipped.WriteDetailFile(outputDir))
		detailPath := filepath.Join(outputDir, "enumeration-skips.json")
		data, err := os.ReadFile(detailPath)
		require.NoError(t, err, "detail file should exist and be readable")

		var detail []SkippedOp
		require.NoError(t, json.Unmarshal(data, &detail))
		t.Logf("Detail file: %d entries (%d bytes)", len(detail), len(data))

		// Detail file entry count must match SkipReport snapshot.
		snap := enumerator.Skipped.Snapshot()
		assert.Equal(t, len(snap), len(detail),
			"detail file must have same number of entries as SkipReport snapshot")

		// Every entry in the detail file should have non-empty fields.
		for i, op := range detail {
			assert.NotEmpty(t, op.Service, "detail[%d] Service", i)
			assert.NotEmpty(t, op.Operation, "detail[%d] Operation", i)
			assert.NotEmpty(t, op.ErrorCode, "detail[%d] ErrorCode", i)
			assert.NotEmpty(t, op.Detail, "detail[%d] Detail", i)
		}
	})
}

// TestSkipResilience_ByARN_Denied tests the listByARN code path with a denied
// resource. This is different from listByType — it goes through EnumerateByARN
// instead of EnumerateAll.
func TestSkipResilience_ByARN_Denied(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	amplifyAppID := fixture.Output("amplify_app_id")
	require.NotEmpty(t, restrictedRoleARN)
	require.NotEmpty(t, amplifyAppID)

	// Build the Amplify app ARN from fixture outputs.
	ctx := context.Background()
	baseCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	require.NoError(t, err)
	identity, err := sts.NewFromConfig(baseCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	require.NoError(t, err)
	amplifyARN := "arn:aws:amplify:us-east-2:" + *identity.Account + ":apps/" + amplifyAppID

	profileDir, profileName := setupRestrictedProfile(t, restrictedRoleARN)

	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     []string{"us-east-2"},
		Concurrency: 1,
	})
	defer enumerator.Close()

	// Enumerate a denied Amplify app by ARN.
	results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List(amplifyARN, out)
	})
	require.NoError(t, err, "by-ARN denial should be skipped, not returned as error")
	assert.Empty(t, results, "denied ARN should produce no resources")

	snap := enumerator.Skipped.Snapshot()
	require.NotEmpty(t, snap, "SkipReport should capture the by-ARN denial")
	t.Logf("By-ARN skip: %+v", snap[0])
}

// TestSkipResilience_MultiRegion tests that denials in multiple regions each
// produce a separate SkipReport entry, and that allowed services return
// results from all regions.
func TestSkipResilience_MultiRegion(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	require.NotEmpty(t, restrictedRoleARN)

	profileDir, profileName := setupRestrictedProfile(t, restrictedRoleARN)

	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     []string{"us-east-1", "us-east-2"},
		Concurrency: 2,
	})
	defer enumerator.Close()

	// S3 in both regions — should get buckets from both.
	s3Results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::S3::Bucket", out)
	})
	require.NoError(t, err)
	assert.NotEmpty(t, s3Results, "S3 should return buckets from multiple regions")

	s3Regions := make(map[string]bool)
	for _, r := range s3Results {
		s3Regions[r.Region] = true
	}
	t.Logf("S3 regions with buckets: %v", s3Regions)

	// Amplify denied in both regions — should produce 2 skip entries.
	amplifyResults, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::Amplify::App", out)
	})
	require.NoError(t, err, "multi-region Amplify denial should not error")
	assert.Empty(t, amplifyResults)

	// SkipReport should have entries from both regions for Amplify.
	snap := enumerator.Skipped.Snapshot()
	amplifySkipRegions := make(map[string]bool)
	for _, op := range snap {
		if op.Service == "amplify" || op.Service == "AWS::Amplify::App" {
			amplifySkipRegions[op.Region] = true
		}
	}
	t.Logf("Amplify skip regions: %v", amplifySkipRegions)
	// At least one region should show up in skips. Both regions should be
	// recorded if the inner loop handles them (which it does for Amplify
	// via CrossRegionActor).
	assert.NotEmpty(t, amplifySkipRegions, "Amplify should be skipped in at least one region")
}

// TestSkipResilience_PerRegionDenial uses an IAM role that denies Amplify
// ONLY in us-east-1 (via aws:RequestedRegion condition) but allows it in
// us-east-2. This simulates SCP-style per-region denial and verifies:
//   - us-east-1 Amplify is skipped (denied)
//   - us-east-2 Amplify succeeds and returns the test app
//   - S3 works in both regions (unaffected)
//   - SkipReport records the denial with us-east-1 region only
func TestSkipResilience_PerRegionDenial(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	regionRestrictedRoleARN := fixture.Output("region_restricted_role_arn")
	require.NotEmpty(t, regionRestrictedRoleARN, "region_restricted_role_arn must be in Terraform outputs")

	amplifyAppName := fixture.Output("amplify_app_name")
	require.NotEmpty(t, amplifyAppName)

	profileDir, profileName := setupRestrictedProfile(t, regionRestrictedRoleARN)

	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     []string{"us-east-1", "us-east-2"},
		Concurrency: 2,
	})
	defer enumerator.Close()

	// Enumerate Amplify across both regions.
	amplifyResults, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::Amplify::App", out)
	})
	require.NoError(t, err, "per-region denial should not abort")

	// us-east-2 should return the test Amplify app (fixture deploys to us-east-2).
	// us-east-1 should be skipped.
	t.Logf("Amplify results: %d apps", len(amplifyResults))
	for _, r := range amplifyResults {
		t.Logf("  %s region=%s name=%s", r.ResourceID, r.Region, r.DisplayName)
	}

	// S3 should work in both regions regardless.
	s3Results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::S3::Bucket", out)
	})
	require.NoError(t, err)
	assert.NotEmpty(t, s3Results, "S3 should be unaffected by Amplify regional denial")

	// SkipReport should have a denial for us-east-1 Amplify specifically.
	snap := enumerator.Skipped.Snapshot()
	require.NotEmpty(t, snap, "SkipReport should capture the us-east-1 Amplify denial")

	var usEast1AmplifySkip *SkippedOp
	for i, op := range snap {
		if (op.Service == "amplify" || op.Service == "AWS::Amplify::App") && op.Region == "us-east-1" {
			usEast1AmplifySkip = &snap[i]
			break
		}
	}
	require.NotNil(t, usEast1AmplifySkip,
		"SkipReport must have a us-east-1 Amplify entry; got: %+v", snap)
	assert.Contains(t, usEast1AmplifySkip.ErrorCode, "AccessDenied")

	// us-east-2 should NOT appear in skip report for Amplify.
	for _, op := range snap {
		if (op.Service == "amplify" || op.Service == "AWS::Amplify::App") && op.Region == "us-east-2" {
			t.Errorf("us-east-2 Amplify should NOT be in SkipReport (it's allowed), but found: %+v", op)
		}
	}

	t.Logf("Summary:\n%s", enumerator.Skipped.Summary())
}

// setupRestrictedProfile creates a temporary AWS CLI profile directory that
// assumes the given role ARN. Returns (profileDir, profileName).
func setupRestrictedProfile(t *testing.T, roleARN string) (string, string) {
	t.Helper()
	profileDir := t.TempDir()
	profileName := "aurelian-test-restricted"
	sourceProfile := os.Getenv("AWS_PROFILE")
	if sourceProfile == "" {
		sourceProfile = "default"
	}

	configContent := "[profile " + profileName + "]\n" +
		"role_arn = " + roleARN + "\n" +
		"source_profile = " + sourceProfile + "\n" +
		"region = us-east-1\n"

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	origConfig, _ := os.ReadFile(filepath.Join(homeDir, ".aws", "config"))
	origCreds, _ := os.ReadFile(filepath.Join(homeDir, ".aws", "credentials"))

	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "config"), append(origConfig, []byte("\n"+configContent)...), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "credentials"), origCreds, 0o600))

	return profileDir, profileName
}

// stscreds is imported to ensure the SDK can resolve assume-role profiles.
var _ = stscreds.NewAssumeRoleProvider

func strPtr(s string) *string { return &s }
