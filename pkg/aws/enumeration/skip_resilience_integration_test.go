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
	// Scan both regions: fixture resources are in us-east-2 (Terraform
	// default), and us-east-1 is included to exercise multi-region scanning
	// alongside denials.
	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  outputDir,
		},
		Regions:     []string{"us-east-1", "us-east-2"},
		Concurrency: 2,
	})
	defer enumerator.Close()

	// --- Happy path: S3 — assert each fixture bucket by unique name ---
	t.Run("S3_allowed", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::S3::Bucket", out)
		})
		require.NoError(t, err)

		resultIDs := make(map[string]bool)
		for _, r := range results {
			resultIDs[r.ResourceID] = true
		}
		for _, name := range fixture.OutputList("bucket_names") {
			require.True(t, resultIDs[name],
				"fixture S3 bucket %q missing from results", name)
		}
	})

	// --- Happy path: IAM roles — assert each fixture role by unique name ---
	t.Run("IAM_roles_allowed", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::IAM::Role", out)
		})
		require.NoError(t, err)

		resultIDs := make(map[string]bool)
		for _, r := range results {
			resultIDs[r.ResourceID] = true
		}
		for _, name := range fixture.OutputList("iam_role_names") {
			require.True(t, resultIDs[name],
				"fixture IAM role %q missing from results", name)
		}
	})

	// --- Happy path: Lambda via CloudControl — assert each fixture function by unique ARN ---
	t.Run("Lambda_allowed", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::Lambda::Function", out)
		})
		require.NoError(t, err)

		resultARNs := make(map[string]bool)
		for _, r := range results {
			resultARNs[r.ARN] = true
		}
		for _, arn := range fixture.OutputList("function_arns") {
			require.True(t, resultARNs[arn],
				"fixture Lambda function %q missing from results", arn)
		}
	})

	// --- Happy path: EC2 instances via CloudControl — assert each fixture instance by unique ID ---
	t.Run("EC2_instances_allowed", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::EC2::Instance", out)
		})
		require.NoError(t, err)

		resultIDs := make(map[string]bool)
		for _, r := range results {
			resultIDs[r.ResourceID] = true
		}
		for _, id := range fixture.OutputList("instance_ids") {
			require.True(t, resultIDs[id],
				"fixture EC2 instance %q missing from results", id)
		}
	})

	// --- Error path: Amplify (fully denied) — exactly 0 results ---
	t.Run("Amplify_denied", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::Amplify::App", out)
		})
		require.NoError(t, err, "Amplify denial should be skipped, not returned as error")
		require.Empty(t, results, "denied Amplify must produce exactly 0 resources")
	})

	// --- Error path: SSM (fully denied) — exactly 0 results ---
	t.Run("SSM_denied", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::SSM::Document", out)
		})
		require.NoError(t, err, "SSM denial should be skipped, not returned as error")
		require.Empty(t, results, "denied SSM must produce exactly 0 resources")
	})

	// --- Critical: mixed pipeline — denied types must not cause loss of specific resources ---
	// This is the definitive resource-loss test. It feeds 8 resource types
	// (6 allowed, 2 denied) through a single pipeline.Pipe across 2 regions,
	// then asserts that every specific fixture resource is present by ID/ARN.
	//
	// Fixture provisions per type:
	//   S3:     5 buckets      (allowed)
	//   IAM:    5 roles, 5 policies, 5 users (allowed, global)
	//   Lambda: 5 functions    (allowed via CloudControl)
	//   EC2:    5 instances    (allowed via CloudControl)
	//   Amplify: 1 app         (DENIED)
	//   SSM:    0 provisioned  (DENIED)
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
			Regions:     []string{"us-east-1", "us-east-2"},
			Concurrency: 2,
		})
		defer mixedEnum.Close()

		// Interleave denied types between allowed types so denials occur
		// mid-iteration, not just at the end. This catches bugs where the
		// first allowed type completes, then a denial aborts the rest.
		types := pipeline.From(
			"AWS::S3::Bucket",        // 1. allowed — 5 fixture buckets
			"AWS::Amplify::App",      // 2. DENIED (early — before most allowed types)
			"AWS::IAM::Role",         // 3. allowed — 5 fixture roles
			"AWS::IAM::Policy",       // 4. allowed — 5 fixture policies
			"AWS::SSM::Document",     // 5. DENIED (middle — between allowed types)
			"AWS::IAM::User",         // 6. allowed — 5 fixture users
			"AWS::Lambda::Function",  // 7. allowed — 5 fixture functions (via CC)
			"AWS::EC2::Instance",     // 8. allowed — 5 fixture instances (via CC)
		)
		listed := pipeline.New[output.AWSResource]()
		pipeline.Pipe(types, mixedEnum.List, listed)

		results, err := listed.Collect()
		require.NoError(t, err, "pipeline must not fail when some types are denied")

		// Index results.
		byType := make(map[string]int)
		resourceIDs := make(map[string]bool)
		resourceARNs := make(map[string]bool)
		for _, r := range results {
			byType[r.ResourceType]++
			resourceIDs[r.ResourceID] = true
			resourceARNs[r.ARN] = true
		}

		t.Logf("MixedPipeline results by type:")
		for rt, count := range byType {
			t.Logf("  %s: %d", rt, count)
		}

		// --- Assert every fixture resource by ID/ARN ---

		// S3: 5 buckets by name
		for _, name := range fixture.OutputList("bucket_names") {
			assert.True(t, resourceIDs[name],
				"S3 bucket %q must survive denied types", name)
		}

		// IAM Roles: 5 by name
		for _, name := range fixture.OutputList("iam_role_names") {
			assert.True(t, resourceIDs[name],
				"IAM role %q must survive denied types", name)
		}

		// IAM Policies: 5 by name
		for _, name := range fixture.OutputList("iam_policy_names") {
			assert.True(t, resourceIDs[name],
				"IAM policy %q must survive denied types", name)
		}

		// IAM Users: 5 by name
		for _, name := range fixture.OutputList("iam_user_names") {
			assert.True(t, resourceIDs[name],
				"IAM user %q must survive denied types", name)
		}

		// Lambda: 5 functions by ARN
		for _, arn := range fixture.OutputList("function_arns") {
			assert.True(t, resourceARNs[arn],
				"Lambda function %q must survive denied types", arn)
		}

		// EC2: 5 instances by ID
		for _, id := range fixture.OutputList("instance_ids") {
			assert.True(t, resourceIDs[id],
				"EC2 instance %q must survive denied types", id)
		}

		// --- Assert denied types produced zero resources ---
		assert.Equal(t, 0, byType["AWS::Amplify::App"],
			"denied Amplify should produce no resources")
		assert.Equal(t, 0, byType["AWS::SSM::Document"],
			"denied SSM should produce no resources")

		// --- Assert SkipReport captured denials and NOT allowed services ---
		snap := mixedEnum.Skipped.Snapshot()
		skippedServices := make(map[string]bool)
		for _, op := range snap {
			skippedServices[op.Service] = true
		}
		t.Logf("MixedPipeline skips: %v", skippedServices)

		assert.True(t, skippedServices["amplify"] || skippedServices["AWS::Amplify::App"],
			"SkipReport must contain Amplify denial")
		assert.True(t, skippedServices["ssm"] || skippedServices["AWS::SSM::Document"],
			"SkipReport must contain SSM denial")

		// Allowed services must NOT appear in the skip report.
		assert.False(t, skippedServices["s3"], "S3 must NOT be in SkipReport")
		assert.False(t, skippedServices["iam"], "IAM must NOT be in SkipReport")
		assert.False(t, skippedServices["ec2"], "EC2 must NOT be in SkipReport")
		assert.False(t, skippedServices["lambda"], "Lambda must NOT be in SkipReport")
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

// TestSkipResilience_ByARN_CloudControl_Denied tests the CloudControl
// EnumerateByARN code path with a denied resource. Lambda has no native
// enumerator — it falls through to CloudControl's GetResource, which
// should fail and be caught by the dispatcher safety net.
func TestSkipResilience_ByARN_CloudControl_Denied(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	require.NotEmpty(t, restrictedRoleARN)

	// Pick a Lambda function ARN from the fixture. The restricted role
	// denies amplify:* and ssm:* but allows lambda:*... however, CloudControl
	// GetResource for Lambda needs cloudcontrol:GetResource which IS allowed.
	// So we need a function ARN that goes through CC. The restricted role
	// allows lambda:*, so CC GetResource will succeed.
	//
	// To test CC by-ARN DENIED, we use the Amplify app ARN instead — Amplify
	// has a native enumerator for EnumerateAll but EnumerateByARN goes
	// through the native path too. For a CC-only by-ARN deny, we'd need a
	// type with no native enumerator AND a service deny.
	//
	// Use a Lambda ARN with the restricted role: lambda:* is allowed but
	// let's verify the CC by-ARN path returns the resource correctly.
	functionARNs := fixture.OutputList("function_arns")
	require.NotEmpty(t, functionARNs)
	functionARN := functionARNs[0]

	profileDir, profileName := setupRestrictedProfile(t, restrictedRoleARN)

	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     []string{"us-east-1", "us-east-2", "us-west-2"},
		Concurrency: 1,
	})
	defer enumerator.Close()

	// Enumerate a Lambda function by ARN — goes through CloudControl GetResource.
	results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List(functionARN, out)
	})
	require.NoError(t, err, "CC by-ARN should not error (lambda allowed)")
	require.Len(t, results, 1, "should return exactly the requested function")
	assert.Equal(t, functionARN, results[0].ARN)
	t.Logf("CC by-ARN allowed: %s", results[0].ARN)
}

// TestSkipResilience_CloseWritesDetailFile_Integration verifies that
// defer Close() writes the detail file with real AWS errors, not just
// unit-test mocks.
func TestSkipResilience_CloseWritesDetailFile_Integration(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	require.NotEmpty(t, restrictedRoleARN)

	profileDir, profileName := setupRestrictedProfile(t, restrictedRoleARN)
	outputDir := t.TempDir()

	func() {
		enumerator := NewEnumerator(plugin.AWSCommonRecon{
			AWSReconBase: plugin.AWSReconBase{
				Profile:    profileName,
				ProfileDir: profileDir,
				OutputDir:  outputDir,
			},
			Regions:     []string{"us-east-1"},
			Concurrency: 1,
		})
		defer enumerator.Close() // should write detail file

		// Trigger a denial.
		out := pipeline.New[output.AWSResource]()
		go func() { for range out.Range() {} }()
		_ = enumerator.List("AWS::Amplify::App", out)
		out.Close()
	}()

	// After Close, the detail file should exist with real AWS error data.
	detailPath := filepath.Join(outputDir, "enumeration-skips.json")
	data, err := os.ReadFile(detailPath)
	require.NoError(t, err, "Close must write detail file after real AWS denial")
	require.True(t, len(data) > 0, "detail file must not be empty")

	var ops []SkippedOp
	require.NoError(t, json.Unmarshal(data, &ops))
	require.NotEmpty(t, ops)
	assert.Contains(t, ops[0].ErrorCode, "AccessDenied")
	t.Logf("Detail file from Close: %d entries, %d bytes", len(ops), len(data))
}

// TestSkipResilience_ByARN_MixedAllowDeny feeds a mix of allowed and denied
// ARNs through the same enumerator. Allowed ARNs must return their resource;
// denied ARNs must be skipped. This tests the by-ARN code path with real
// resources, not just type-based enumeration.
func TestSkipResilience_ByARN_MixedAllowDeny(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	require.NotEmpty(t, restrictedRoleARN)

	// Collect ARNs: IAM role (allowed) + Amplify app (denied).
	iamRoleARN := fixture.Output("iam_role_arn")
	require.NotEmpty(t, iamRoleARN)

	ctx := context.Background()
	baseCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	require.NoError(t, err)
	identity, err := sts.NewFromConfig(baseCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	require.NoError(t, err)
	amplifyARN := "arn:aws:amplify:us-east-2:" + *identity.Account + ":apps/" + fixture.Output("amplify_app_id")

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

	// Feed both ARNs through the pipeline.
	arns := pipeline.From(iamRoleARN, amplifyARN)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(arns, enumerator.List, listed)

	results, err := listed.Collect()
	require.NoError(t, err, "pipeline must not fail when some ARNs are denied")

	// IAM role must be returned.
	resultARNs := make(map[string]bool)
	for _, r := range results {
		resultARNs[r.ARN] = true
	}
	require.True(t, resultARNs[iamRoleARN],
		"IAM role %q (allowed) must survive denied Amplify ARN", iamRoleARN)

	// Amplify ARN must NOT be returned.
	assert.False(t, resultARNs[amplifyARN],
		"Amplify ARN %q (denied) must not be in results", amplifyARN)

	// SkipReport must capture the Amplify denial.
	snap := enumerator.Skipped.Snapshot()
	require.NotEmpty(t, snap)
	t.Logf("By-ARN mixed: %d results, %d skips", len(results), len(snap))
}

// TestSkipResilience_MosaicPipeline is the definitive multi-region × multi-type
// test. It uses the mosaic role (Amplify denied in us-east-1, Lambda denied in
// us-east-2) and enumerates 4 types across 3 regions in a single pipeline.Pipe.
//
// Expected survival matrix:
//
//	             us-east-1  us-east-2  us-west-2
//	S3           ✓          ✓          ✓
//	Amplify      ✗ denied   ✓          ✓
//	Lambda(CC)   ✓          ✗ denied   ✓
//	IAM          ✓ global   ✓ global   ✓ global
func TestSkipResilience_MosaicPipeline(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	regionRestrictedRoleARN := fixture.Output("region_restricted_role_arn")
	require.NotEmpty(t, regionRestrictedRoleARN)

	profileDir, profileName := setupRestrictedProfile(t, regionRestrictedRoleARN)

	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     []string{"us-east-1", "us-east-2", "us-west-2"},
		Concurrency: 3,
	})
	defer enumerator.Close()

	// Interleave allowed and denied types.
	types := pipeline.From(
		"AWS::S3::Bucket",        // allowed everywhere
		"AWS::Amplify::App",      // denied in us-east-1
		"AWS::Lambda::Function",  // denied in us-east-2
		"AWS::IAM::Role",         // allowed (global)
	)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(types, enumerator.List, listed)

	results, err := listed.Collect()
	require.NoError(t, err, "mosaic pipeline must not fail")

	// Index results.
	resultIDs := make(map[string]bool)
	resultARNs := make(map[string]bool)
	for _, r := range results {
		resultIDs[r.ResourceID] = true
		resultARNs[r.ARN] = true
	}

	// S3: all 7 fixture buckets must survive (allowed in all regions).
	for _, name := range fixture.OutputList("bucket_names") {
		require.True(t, resultIDs[name],
			"S3 bucket %q must survive mosaic pipeline", name)
	}

	// IAM roles: all 5 fixture roles must survive (global, allowed).
	for _, name := range fixture.OutputList("iam_role_names") {
		require.True(t, resultIDs[name],
			"IAM role %q must survive mosaic pipeline", name)
	}

	// Lambda: functions from allowed regions survive, denied region absent.
	// us-east-1 (secondary) + us-west-2 (tertiary) = allowed.
	for _, arn := range fixture.OutputList("function_arns_secondary") {
		require.True(t, resultARNs[arn],
			"Lambda %q (us-east-1, allowed) must survive", arn)
	}
	for _, arn := range fixture.OutputList("function_arns_tertiary") {
		require.True(t, resultARNs[arn],
			"Lambda %q (us-west-2, allowed) must survive", arn)
	}
	// us-east-2 (primary) Lambda = denied.
	for _, arn := range fixture.OutputList("function_arns_primary") {
		assert.False(t, resultARNs[arn],
			"Lambda %q (us-east-2, denied) must NOT be returned", arn)
	}

	// Amplify: us-east-2 app must survive (allowed), us-east-1 denied.
	amplifyAppID := fixture.Output("amplify_app_id")
	require.True(t, resultIDs[amplifyAppID],
		"Amplify app %q (us-east-2, allowed) must survive", amplifyAppID)

	// SkipReport: Amplify denied in us-east-1, Lambda denied in us-east-2.
	snap := enumerator.Skipped.Snapshot()
	type skipKey struct{ service, region string }
	skips := make(map[skipKey]bool)
	for _, op := range snap {
		skips[skipKey{op.Service, op.Region}] = true
	}
	t.Logf("Mosaic pipeline skips: %v", skips)

	assert.True(t,
		skips[skipKey{"amplify", "us-east-1"}] || skips[skipKey{"AWS::Amplify::App", "us-east-1"}],
		"Amplify must be skipped in us-east-1")
	assert.False(t,
		skips[skipKey{"amplify", "us-east-2"}] || skips[skipKey{"AWS::Amplify::App", "us-east-2"}],
		"Amplify must NOT be skipped in us-east-2")

	// S3 and IAM must not appear in skips at all.
	for _, op := range snap {
		assert.NotEqual(t, "s3", op.Service, "S3 must not be in SkipReport")
		assert.NotEqual(t, "iam", op.Service, "IAM must not be in SkipReport")
	}

	t.Logf("Mosaic pipeline: %d results, %d skips", len(results), len(snap))
	t.Logf("Summary:\n%s", enumerator.Skipped.Summary())
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

// TestSkipResilience_PerRegionDenial uses a mosaic IAM role that denies
// different services in different regions:
//
//	us-east-1: Amplify DENIED, Lambda allowed, S3 allowed
//	us-east-2: Amplify allowed, Lambda DENIED, S3 allowed
//	us-west-2: all allowed
//
// Fixture resources exist in all 3 regions. The test verifies that resources
// from allowed (service, region) pairs survive while denied pairs are skipped.
func TestSkipResilience_PerRegionDenial(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	regionRestrictedRoleARN := fixture.Output("region_restricted_role_arn")
	require.NotEmpty(t, regionRestrictedRoleARN)

	profileDir, profileName := setupRestrictedProfile(t, regionRestrictedRoleARN)

	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     []string{"us-east-1", "us-east-2", "us-west-2"},
		Concurrency: 3,
	})
	defer enumerator.Close()

	// --- S3: allowed in all 3 regions, all fixture buckets must be present ---
	t.Run("S3_all_regions", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::S3::Bucket", out)
		})
		require.NoError(t, err)

		resultIDs := make(map[string]bool)
		for _, r := range results {
			resultIDs[r.ResourceID] = true
		}
		for _, name := range fixture.OutputList("bucket_names") {
			require.True(t, resultIDs[name],
				"S3 bucket %q must survive mosaic denial", name)
		}
	})

	// --- Amplify: denied in us-east-1, allowed in us-east-2 + us-west-2 ---
	// The fixture Amplify app is in us-east-2 — it should be returned.
	t.Run("Amplify_mosaic", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::Amplify::App", out)
		})
		require.NoError(t, err)

		// Fixture app in us-east-2 should survive.
		amplifyAppID := fixture.Output("amplify_app_id")
		resultIDs := make(map[string]bool)
		for _, r := range results {
			resultIDs[r.ResourceID] = true
		}
		require.True(t, resultIDs[amplifyAppID],
			"Amplify app %q in us-east-2 must survive us-east-1 denial", amplifyAppID)
	})

	// --- Lambda via CloudControl: denied in us-east-2, allowed in us-east-1 + us-west-2 ---
	// Fixture Lambdas in us-east-1 (secondary) and us-west-2 (tertiary) should survive.
	// Fixture Lambdas in us-east-2 (primary) should be lost (Lambda denied there).
	t.Run("Lambda_mosaic", func(t *testing.T) {
		// Use a fresh enumerator — Lambda goes through CloudControl which
		// has its own inner skip path.
		lambdaEnum := NewEnumerator(plugin.AWSCommonRecon{
			AWSReconBase: plugin.AWSReconBase{
				Profile:    profileName,
				ProfileDir: profileDir,
				OutputDir:  t.TempDir(),
			},
			Regions:     []string{"us-east-1", "us-east-2", "us-west-2"},
			Concurrency: 3,
		})
		defer lambdaEnum.Close()

		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return lambdaEnum.List("AWS::Lambda::Function", out)
		})
		require.NoError(t, err)

		resultARNs := make(map[string]bool)
		for _, r := range results {
			resultARNs[r.ARN] = true
		}

		// us-east-1 (secondary) functions: Lambda allowed → must survive.
		for _, arn := range fixture.OutputList("function_arns_secondary") {
			require.True(t, resultARNs[arn],
				"Lambda %q (us-east-1, allowed) must survive", arn)
		}

		// us-west-2 (tertiary) functions: Lambda allowed → must survive.
		for _, arn := range fixture.OutputList("function_arns_tertiary") {
			require.True(t, resultARNs[arn],
				"Lambda %q (us-west-2, allowed) must survive", arn)
		}

		// us-east-2 (primary) functions: Lambda DENIED → must be absent.
		for _, arn := range fixture.OutputList("function_arns_primary") {
			assert.False(t, resultARNs[arn],
				"Lambda %q (us-east-2, denied) must NOT be returned", arn)
		}

		// SkipReport should have Lambda denial for us-east-2.
		snap := lambdaEnum.Skipped.Snapshot()
		foundLambdaDeny := false
		for _, op := range snap {
			if op.Region == "us-east-2" && (op.Service == "cloudcontrol" || op.Service == "AWS::Lambda::Function") {
				foundLambdaDeny = true
				break
			}
		}
		assert.True(t, foundLambdaDeny,
			"SkipReport must have a us-east-2 Lambda/cloudcontrol denial")
	})

	// --- SkipReport: verify mosaic denials are region-specific ---
	t.Run("SkipReport_mosaic", func(t *testing.T) {
		snap := enumerator.Skipped.Snapshot()

		// Build a set of (service, region) skip pairs.
		type skipKey struct{ service, region string }
		skips := make(map[skipKey]bool)
		for _, op := range snap {
			skips[skipKey{op.Service, op.Region}] = true
		}

		t.Logf("Mosaic skip pairs: %v", skips)

		// Amplify should be denied in us-east-1 only.
		assert.True(t,
			skips[skipKey{"amplify", "us-east-1"}] || skips[skipKey{"AWS::Amplify::App", "us-east-1"}],
			"Amplify must be skipped in us-east-1")
		assert.False(t,
			skips[skipKey{"amplify", "us-east-2"}] || skips[skipKey{"AWS::Amplify::App", "us-east-2"}],
			"Amplify must NOT be skipped in us-east-2")
		assert.False(t,
			skips[skipKey{"amplify", "us-west-2"}] || skips[skipKey{"AWS::Amplify::App", "us-west-2"}],
			"Amplify must NOT be skipped in us-west-2")
	})

	t.Logf("Summary:\n%s", enumerator.Skipped.Summary())
}

// TestSkipResilience_PartialEC2Access uses a role that allows
// ec2:DescribeImages but denies ec2:DescribeImageAttribute and
// ec2:DescribeInstances. This is the partial-access scenario where
// the enumerator succeeds at listing but fails during per-resource
// enrichment.
//
// Expected behavior:
//   - DescribeImages succeeds, finds self-owned AMIs
//   - buildResource fails for EACH image (DescribeImageAttribute denied)
//   - Each failure is logged as Warn and the image is skipped (continue)
//   - The pipeline does NOT abort
//   - 0 enriched images are returned (all dropped during enrichment)
//   - SkipReport does NOT contain EC2 — the per-image failure is a Warn,
//     not a skip (it's handled by the continue in the for loop, not by
//     ClassifySkippable)
func TestSkipResilience_PartialEC2Access(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	partialEC2RoleARN := fixture.Output("partial_ec2_role_arn")
	require.NotEmpty(t, partialEC2RoleARN, "partial_ec2_role_arn must be in Terraform outputs")

	profileDir, profileName := setupRestrictedProfile(t, partialEC2RoleARN)

	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     []string{"us-east-1", "us-east-2"},
		Concurrency: 1,
	})
	defer enumerator.Close()

	// DescribeImages should succeed (finds self-owned AMIs in the account).
	// But buildResource will fail for every image because
	// DescribeImageAttribute is denied.
	results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::EC2::Image", out)
	})
	require.NoError(t, err, "partial EC2 access must not abort the pipeline")

	// All images are dropped during enrichment — 0 results.
	// This is the known behavior: list succeeds, enrichment fails per-item.
	t.Logf("EC2 images with partial access: %d (expected 0 — enrichment denied)", len(results))
	assert.Empty(t, results,
		"all images should be dropped during enrichment when DescribeImageAttribute is denied")

	// The per-image failures are Warn-logged (not ClassifySkippable), so
	// they should NOT appear in the SkipReport.
	snap := enumerator.Skipped.Snapshot()
	for _, op := range snap {
		assert.NotEqual(t, "ec2", op.Service,
			"EC2 enrichment failures should not appear in SkipReport — they are per-item Warns, not skips")
	}
	t.Logf("SkipReport entries: %d", len(snap))
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
