//go:build integration

package enumeration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSkipResilience_RestrictedRole uses a role that allows S3, IAM, EC2,
// Lambda but denies Amplify and SSM. Sub-tests enumerate each type and
// assert specific fixture resources by unique ID.
func TestSkipResilience_RestrictedRole(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	require.NotEmpty(t, restrictedRoleARN)

	enumerator := newRestrictedEnumerator(t, fixture, restrictedRoleARN)
	defer enumerator.Close()

	t.Run("S3_allowed", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::S3::Bucket", out)
		})
		require.NoError(t, err)
		assertFixtureResourcesByARN(t, results, fixture.OutputList("bucket_arns"))
	})

	t.Run("IAM_roles_allowed", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::IAM::Role", out)
		})
		require.NoError(t, err)
		assertFixtureResourcesByARN(t, results, fixture.OutputList("iam_role_arns"))
	})

	t.Run("Lambda_allowed", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::Lambda::Function", out)
		})
		require.NoError(t, err)
		assertFixtureResourcesByARN(t, results, fixture.OutputList("function_arns"))
	})

	t.Run("EC2_instances_allowed", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::EC2::Instance", out)
		})
		require.NoError(t, err)
		assertFixtureResourcesByARN(t, results, fixture.OutputList("instance_arns"))
	})

	t.Run("Amplify_denied", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::Amplify::App", out)
		})
		require.NoError(t, err)
		require.Empty(t, results, "denied Amplify must produce exactly 0 resources")
	})

	t.Run("SSM_denied", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::SSM::Document", out)
		})
		require.NoError(t, err)
		require.Empty(t, results, "denied SSM must produce exactly 0 resources")
	})

	t.Run("EC2_images_allowed", func(t *testing.T) {
		_, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::EC2::Image", out)
		})
		require.NoError(t, err, "EC2 image enumeration should not abort")
	})

	// MixedPipeline: interleave allowed and denied types, assert every
	// fixture resource survives. Fresh enumerator (IAM sync.Once).
	t.Run("MixedPipeline_no_resource_loss", func(t *testing.T) {
		mixedEnum := newRestrictedEnumerator(t, fixture, restrictedRoleARN)
		defer mixedEnum.Close()

		types := pipeline.From(
			"AWS::S3::Bucket",
			"AWS::Amplify::App", // DENIED
			"AWS::IAM::Role",
			"AWS::IAM::Policy",
			"AWS::SSM::Document", // DENIED
			"AWS::IAM::User",
			"AWS::Lambda::Function",
			"AWS::EC2::Instance",
		)
		listed := pipeline.New[output.AWSResource]()
		pipeline.Pipe(types, mixedEnum.List, listed)
		results, err := listed.Collect()
		require.NoError(t, err)

		resultARNs := indexARNs(results)

		assertAllPresent(t, resultARNs, fixture.OutputList("bucket_arns"), "S3 bucket")
		assertAllPresent(t, resultARNs, fixture.OutputList("iam_role_arns"), "IAM role")
		assertAllPresent(t, resultARNs, fixture.OutputList("iam_policy_arns"), "IAM policy")
		assertAllPresent(t, resultARNs, fixture.OutputList("iam_user_arns"), "IAM user")
		assertAllPresent(t, resultARNs, fixture.OutputList("function_arns"), "Lambda function")
		assertAllPresent(t, resultARNs, fixture.OutputList("instance_arns"), "EC2 instance")

		snap := mixedEnum.Skipped.Snapshot()
		skippedServices := indexSkipServices(snap)
		assert.True(t, skippedServices["amplify"])
		assert.True(t, skippedServices["ssm"])
		// Allowed services must NOT appear in SkipReport.
		assert.False(t, skippedServices["s3"], "S3 must NOT be in SkipReport")
		assert.False(t, skippedServices["iam"], "IAM must NOT be in SkipReport")
		assert.False(t, skippedServices["ec2"], "EC2 must NOT be in SkipReport")
		assert.False(t, skippedServices["lambda"], "Lambda must NOT be in SkipReport")
	})

	t.Run("SkipReport_completeness", func(t *testing.T) {
		snap := enumerator.Skipped.Snapshot()
		require.NotEmpty(t, snap)

		// Every skip must use the short service name from the inner loop,
		// NOT a CloudControl type string. This is enforced at the unit-test
		// level by TestClassifySkippableServiceNames (AST check), but we
		// verify it here with real AWS errors too.
		for _, op := range snap {
			assert.False(t, strings.HasPrefix(op.Service, "AWS::"),
				"SkipReport entry has Service=%q — inner loop ClassifySkippable wiring may be broken", op.Service)
		}
	})

	t.Run("Summary_and_detail_file", func(t *testing.T) {
		summary := enumerator.Skipped.Summary()
		require.NotEmpty(t, summary)

		require.NoError(t, enumerator.Skipped.WriteDetailFile(enumerator.outputDir))
		data, err := os.ReadFile(filepath.Join(enumerator.outputDir, "enumeration-skips.json"))
		require.NoError(t, err)

		var detail []SkippedOp
		require.NoError(t, json.Unmarshal(data, &detail))
		snap := enumerator.Skipped.Snapshot()
		assert.Equal(t, len(snap), len(detail))
		for i, op := range detail {
			assert.NotEmpty(t, op.Service, "detail[%d] Service", i)
			assert.NotEmpty(t, op.ErrorCode, "detail[%d] ErrorCode", i)
		}
	})
}

// TestSkipResilience_ByARN_Denied tests the by-ARN code path with a denied resource.
func TestSkipResilience_ByARN_Denied(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	amplifyARN := fixture.Output("amplify_app_arn")
	require.NotEmpty(t, restrictedRoleARN)
	require.NotEmpty(t, amplifyARN)

	enumerator := newRestrictedEnumerator(t, fixture, restrictedRoleARN)
	defer enumerator.Close()

	results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List(amplifyARN, out)
	})
	require.NoError(t, err)
	assert.Empty(t, results)
	require.NotEmpty(t, enumerator.Skipped.Snapshot())
}

// TestSkipResilience_ByARN_CloudControl tests CC GetResource by ARN (happy path).
func TestSkipResilience_ByARN_CloudControl(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	require.NotEmpty(t, restrictedRoleARN)

	functionARNs := fixture.OutputList("function_arns")
	require.NotEmpty(t, functionARNs)

	enumerator := newRestrictedEnumerator(t, fixture, restrictedRoleARN)
	defer enumerator.Close()

	results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List(functionARNs[0], out)
	})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, functionARNs[0], results[0].ARN)
}

// TestSkipResilience_ByARN_MixedAllowDeny: pipeline of allowed + denied ARNs.
func TestSkipResilience_ByARN_MixedAllowDeny(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	iamRoleARN := fixture.Output("iam_role_arn")
	amplifyARN := fixture.Output("amplify_app_arn")
	require.NotEmpty(t, restrictedRoleARN)
	require.NotEmpty(t, iamRoleARN)
	require.NotEmpty(t, amplifyARN)

	enumerator := newRestrictedEnumerator(t, fixture, restrictedRoleARN)
	defer enumerator.Close()

	arns := pipeline.From(iamRoleARN, amplifyARN)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(arns, enumerator.List, listed)
	results, err := listed.Collect()
	require.NoError(t, err)

	resultARNs := indexARNs(results)
	require.True(t, resultARNs[iamRoleARN], "IAM role (allowed) must survive")
	assert.False(t, resultARNs[amplifyARN], "Amplify (denied) must be absent")
	require.NotEmpty(t, enumerator.Skipped.Snapshot())
}

// TestSkipResilience_MultiRegion: same type denied in all scanned regions.
func TestSkipResilience_MultiRegion(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	require.NotEmpty(t, restrictedRoleARN)

	enumerator := newRestrictedEnumerator(t, fixture, restrictedRoleARN)
	defer enumerator.Close()

	// S3 across all regions — assert every fixture bucket by ARN.
	s3Results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::S3::Bucket", out)
	})
	require.NoError(t, err)
	assertFixtureResourcesByARN(t, s3Results, fixture.OutputList("bucket_arns"))

	// Amplify denied in all regions (restricted role denies amplify:*).
	amplifyResults, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::Amplify::App", out)
	})
	require.NoError(t, err)
	assert.Empty(t, amplifyResults)

	snap := enumerator.Skipped.Snapshot()
	amplifySkipRegions := make(map[string]bool)
	for _, op := range snap {
		if op.Service == "amplify" {
			amplifySkipRegions[op.Region] = true
		}
		// Must not have CC type strings — indicates broken inner-loop wiring.
		assert.False(t, strings.HasPrefix(op.Service, "AWS::"),
			"SkipReport has CC type %q — inner loop wiring broken", op.Service)
	}
	assert.NotEmpty(t, amplifySkipRegions)
}

// TestSkipResilience_PerRegionDenial: mosaic role — different services denied
// in different regions. All regions and deny mappings come from Terraform.
func TestSkipResilience_PerRegionDenial(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	roleARN := fixture.Output("region_restricted_role_arn")
	require.NotEmpty(t, roleARN)

	denyAmplifyRegion := fixture.Output("mosaic_deny_amplify_region")
	denyLambdaRegion := fixture.Output("mosaic_deny_lambda_region")
	require.NotEmpty(t, denyAmplifyRegion)
	require.NotEmpty(t, denyLambdaRegion)

	enumerator := newRestrictedEnumerator(t, fixture, roleARN)
	defer enumerator.Close()

	// S3: allowed everywhere — all fixture buckets must survive by ARN.
	t.Run("S3_all_regions", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::S3::Bucket", out)
		})
		require.NoError(t, err)
		assertFixtureResourcesByARN(t, results, fixture.OutputList("bucket_arns"))
	})

	// Amplify: denied in denyAmplifyRegion, allowed elsewhere.
	// Fixture app is in primary region — should survive if primary != deny region.
	t.Run("Amplify_mosaic", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::Amplify::App", out)
		})
		require.NoError(t, err)

		amplifyARN := fixture.Output("amplify_app_arn")
		resultARNs := indexARNs(results)
		require.True(t, resultARNs[amplifyARN],
			"Amplify app %q must survive (not in deny region %s)", amplifyARN, denyAmplifyRegion)
	})

	// Lambda: denied in denyLambdaRegion (primary). Functions from
	// secondary + tertiary regions should survive.
	t.Run("Lambda_mosaic", func(t *testing.T) {
		lambdaEnum := newRestrictedEnumerator(t, fixture, roleARN)
		defer lambdaEnum.Close()

		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return lambdaEnum.List("AWS::Lambda::Function", out)
		})
		require.NoError(t, err)

		resultARNs := indexARNs(results)

		// Secondary + tertiary functions: allowed.
		for _, arn := range fixture.OutputList("function_arns_secondary") {
			require.True(t, resultARNs[arn], "Lambda %q (allowed region) must survive", arn)
		}
		for _, arn := range fixture.OutputList("function_arns_tertiary") {
			require.True(t, resultARNs[arn], "Lambda %q (allowed region) must survive", arn)
		}
		// Primary functions: denied.
		for _, arn := range fixture.OutputList("function_arns_primary") {
			assert.False(t, resultARNs[arn], "Lambda %q (denied in %s) must NOT be returned", arn, denyLambdaRegion)
		}

		snap := lambdaEnum.Skipped.Snapshot()
		foundDeny := false
		for _, op := range snap {
			if op.Region == denyLambdaRegion {
				foundDeny = true
				break
			}
		}
		assert.True(t, foundDeny, "SkipReport must have denial for region %s", denyLambdaRegion)
	})

	// SkipReport: Amplify denied in denyAmplifyRegion only.
	t.Run("SkipReport_mosaic", func(t *testing.T) {
		snap := enumerator.Skipped.Snapshot()
		type skipKey struct{ service, region string }
		skips := make(map[skipKey]bool)
		for _, op := range snap {
			skips[skipKey{op.Service, op.Region}] = true
		}

		assert.True(t,
			skips[skipKey{"amplify", denyAmplifyRegion}],
			"Amplify must be skipped in %s", denyAmplifyRegion)

		// Check Amplify is NOT skipped in other regions.
		for _, region := range fixture.OutputList("test_regions") {
			if region == denyAmplifyRegion {
				continue
			}
			assert.False(t,
				skips[skipKey{"amplify", region}],
				"Amplify must NOT be skipped in %s (only denied in %s)", region, denyAmplifyRegion)
		}
	})
}

// TestSkipResilience_MosaicPipeline: 4 types × all regions, mosaic deny.
func TestSkipResilience_MosaicPipeline(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	roleARN := fixture.Output("region_restricted_role_arn")
	denyLambdaRegion := fixture.Output("mosaic_deny_lambda_region")
	require.NotEmpty(t, roleARN)
	require.NotEmpty(t, denyLambdaRegion)

	enumerator := newRestrictedEnumerator(t, fixture, roleARN)
	defer enumerator.Close()

	types := pipeline.From(
		"AWS::S3::Bucket",
		"AWS::Amplify::App",
		"AWS::Lambda::Function",
		"AWS::IAM::Role",
	)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(types, enumerator.List, listed)
	results, err := listed.Collect()
	require.NoError(t, err)

	resultARNs := indexARNs(results)

	// S3: all buckets by ARN.
	assertAllPresent(t, resultARNs, fixture.OutputList("bucket_arns"), "S3 bucket")

	// IAM: all roles by ARN.
	assertAllPresent(t, resultARNs, fixture.OutputList("iam_role_arns"), "IAM role")

	// Amplify: app must survive (not in deny region).
	amplifyARN := fixture.Output("amplify_app_arn")
	require.True(t, resultARNs[amplifyARN], "Amplify app %q must survive", amplifyARN)

	// Lambda: secondary + tertiary survive, primary absent.
	assertAllPresent(t, resultARNs, fixture.OutputList("function_arns_secondary"), "Lambda (allowed)")
	assertAllPresent(t, resultARNs, fixture.OutputList("function_arns_tertiary"), "Lambda (allowed)")
	for _, arn := range fixture.OutputList("function_arns_primary") {
		assert.False(t, resultARNs[arn], "Lambda %q (denied in %s) must NOT be returned", arn, denyLambdaRegion)
	}

	// SkipReport: no S3 or IAM.
	snap := enumerator.Skipped.Snapshot()
	for _, op := range snap {
		assert.NotEqual(t, "s3", op.Service)
		assert.NotEqual(t, "iam", op.Service)
	}
}

// TestSkipResilience_PartialEC2Access: DescribeImages allowed, DescribeImageAttribute denied.
func TestSkipResilience_PartialEC2Access(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	// Precondition: verify the account has self-owned AMIs using the
	// unrestricted role. If it doesn't, this test is meaningless.
	fullAccessEnum := newRestrictedEnumerator(t, fixture, fixture.Output("restricted_role_arn"))
	fullResults, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return fullAccessEnum.List("AWS::EC2::Image", out)
	})
	fullAccessEnum.Close()
	require.NoError(t, err)
	if len(fullResults) == 0 {
		t.Skip("no self-owned AMIs in account — partial EC2 test is not meaningful")
	}
	t.Logf("precondition: %d self-owned AMIs found with full access", len(fullResults))

	// Now run with the partial-EC2 role (DescribeImages OK, DescribeImageAttribute denied).
	roleARN := fixture.Output("partial_ec2_role_arn")
	require.NotEmpty(t, roleARN)

	enumerator := newRestrictedEnumerator(t, fixture, roleARN)
	defer enumerator.Close()

	results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::EC2::Image", out)
	})
	require.NoError(t, err)
	assert.Empty(t, results,
		"all %d images should fail enrichment (DescribeImageAttribute denied)", len(fullResults))

	// Per-item failures are Warns, not skips.
	for _, op := range enumerator.Skipped.Snapshot() {
		assert.NotEqual(t, "ec2", op.Service)
	}
}

// TestSkipResilience_WiringCheck is the systematic behavioral test that
// exercises every native enumerator's ClassifySkippable inner-loop wiring.
// It uses the wiring-check role which denies ALL enumerated services, so
// every enumerator type is forced through its error-handling path.
//
// For each type, it verifies:
//   - List returns no error (skipped, not propagated)
//   - SkipReport has an entry with the correct short service name
//   - No entry has an AWS:: prefix (would indicate broken inner loop)
//
// This is the behavioral complement to the AST checks — it catches
// "correct pattern in dead code" and runtime wiring failures that
// static analysis can't detect.
func TestSkipResilience_WiringCheck(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	roleARN := fixture.Output("wiring_check_role_arn")
	require.NotEmpty(t, roleARN)

	resourceTypes := fixture.OutputList("wiring_check_resource_types")
	expectedServices := fixture.OutputList("wiring_check_denied_services")
	require.NotEmpty(t, resourceTypes)
	require.Equal(t, len(resourceTypes), len(expectedServices),
		"wiring_check_resource_types and wiring_check_denied_services must have same length")

	enumerator := newRestrictedEnumerator(t, fixture, roleARN)
	defer enumerator.Close()

	// Enumerate every type — all should be denied.
	for i, resourceType := range resourceTypes {
		expectedService := expectedServices[i]
		t.Run(expectedService, func(t *testing.T) {
			results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
				return enumerator.List(resourceType, out)
			})
			require.NoError(t, err, "%s should be skipped, not returned as error", resourceType)
			assert.Empty(t, results, "%s should produce 0 resources (denied)", resourceType)
		})
	}

	// Verify SkipReport has entries for every denied service with exact short names.
	snap := enumerator.Skipped.Snapshot()
	require.NotEmpty(t, snap)

	skippedServices := make(map[string]bool)
	for _, op := range snap {
		skippedServices[op.Service] = true
		// No AWS:: prefix — that would indicate dispatcher fallback, not inner loop.
		require.False(t, strings.HasPrefix(op.Service, "AWS::"),
			"SkipReport entry Service=%q uses CC type string — inner loop ClassifySkippable "+
				"wiring is broken for this enumerator. The error fell through to the "+
				"dispatcher safety net which records the raw identifier.", op.Service)
	}

	for _, svc := range expectedServices {
		assert.True(t, skippedServices[svc],
			"SkipReport must contain service %q. Found: %v. "+
				"This means the enumerator's inner ClassifySkippable may be in dead code "+
				"or not wired correctly.", svc, skippedServices)
	}

	t.Logf("Wiring check: %d skip entries, services: %v", len(snap), skippedServices)
}

// TestSkipResilience_ResourcePolicyDeny tests that a bucket with a
// resource-based deny policy (bucket policy) is handled during by-ARN
// enumeration. The restricted role has s3:* via IAM, but the bucket policy
// explicitly denies HeadBucket for that role. This is a different denial
// path than IAM-based deny — the error comes from the resource policy, not
// the identity policy.
func TestSkipResilience_ResourcePolicyDeny(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	policyDeniedBucketARN := fixture.Output("policy_denied_bucket_arn")
	policyDeniedBucketName := fixture.Output("policy_denied_bucket_name")
	require.NotEmpty(t, restrictedRoleARN)
	require.NotEmpty(t, policyDeniedBucketARN)

	enumerator := newRestrictedEnumerator(t, fixture, restrictedRoleARN)
	defer enumerator.Close()

	// By-ARN: HeadBucket is denied by bucket policy. Should skip, not abort.
	t.Run("ByARN_bucket_policy_deny", func(t *testing.T) {
		bucketARNForList := "arn:aws:s3:::" + policyDeniedBucketName
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List(bucketARNForList, out)
		})
		require.NoError(t, err, "bucket-policy denial must be skipped, not returned as error")
		assert.Empty(t, results, "resource-policy denied bucket should produce 0 results")
	})

	// ListBuckets (type-based): the bucket should still appear because
	// ListBuckets is account-level and not subject to bucket policies.
	// This proves that resource-policy deny only affects per-bucket ops,
	// not the list.
	t.Run("ListBuckets_still_returns_policy_denied_bucket", func(t *testing.T) {
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::S3::Bucket", out)
		})
		require.NoError(t, err)

		resultIDs := make(map[string]bool)
		for _, r := range results {
			resultIDs[r.ResourceID] = true
		}
		assert.True(t, resultIDs[policyDeniedBucketName],
			"policy-denied bucket %q must still appear in ListBuckets (account-level API)", policyDeniedBucketName)
	})
}

// TestSkipResilience_CloseWritesDetailFile: defer Close() writes detail file with real errors.
func TestSkipResilience_CloseWritesDetailFile(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	require.NotEmpty(t, restrictedRoleARN)

	outputDir := t.TempDir()
	func() {
		profileDir, profileName := setupRestrictedProfile(t, restrictedRoleARN)
		regions := fixture.OutputList("test_regions")
		e := NewEnumerator(plugin.AWSCommonRecon{
			AWSReconBase: plugin.AWSReconBase{
				Profile:    profileName,
				ProfileDir: profileDir,
				OutputDir:  outputDir,
			},
			Regions:     regions,
			Concurrency: len(regions),
		})
		defer e.Close()

		out := pipeline.New[output.AWSResource]()
		go func() {
			for range out.Range() {
			}
		}()
		_ = e.List("AWS::Amplify::App", out)
		out.Close()
	}()

	data, err := os.ReadFile(filepath.Join(outputDir, "enumeration-skips.json"))
	require.NoError(t, err)
	require.True(t, len(data) > 0)

	var ops []SkippedOp
	require.NoError(t, json.Unmarshal(data, &ops))
	require.NotEmpty(t, ops)
	assert.Contains(t, ops[0].ErrorCode, "AccessDenied")
}

// --- Helpers ---

// newRestrictedEnumerator creates an enumerator using a restricted role,
// scanning all regions from Terraform outputs.
func newRestrictedEnumerator(t *testing.T, fixture testutil.Fixture, roleARN string) *Enumerator {
	t.Helper()
	profileDir, profileName := setupRestrictedProfile(t, roleARN)
	regions := fixture.OutputList("test_regions")
	require.NotEmpty(t, regions)

	return NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     regions,
		Concurrency: len(regions),
	})
}

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

func indexARNs(results []output.AWSResource) map[string]bool {
	m := make(map[string]bool)
	for _, r := range results {
		m[r.ARN] = true
	}
	return m
}

func indexSkipServices(snap []SkippedOp) map[string]bool {
	m := make(map[string]bool)
	for _, op := range snap {
		m[op.Service] = true
	}
	return m
}

func assertFixtureResourcesByARN(t *testing.T, results []output.AWSResource, expected []string) {
	t.Helper()
	arns := indexARNs(results)
	for _, arn := range expected {
		require.True(t, arns[arn], "fixture resource %q missing from results", arn)
	}
}

func assertAllPresent(t *testing.T, index map[string]bool, expected []string, label string) {
	t.Helper()
	for _, key := range expected {
		require.True(t, index[key], "%s %q must be present", label, key)
	}
}

var _ = stscreds.NewAssumeRoleProvider

func strPtr(s string) *string { return &s }
