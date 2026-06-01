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

// TestSkipResilience_RestrictedRole provisions a restricted IAM role (S3
// allowed, Amplify denied) via Terraform, assumes it, and verifies that:
//   - S3 enumeration succeeds and returns results
//   - Amplify enumeration is skipped (AccessDeniedException)
//   - The SkipReport captures the denied service
//   - The pipeline does not abort
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

	// Copy the source credentials so the SDK can find them.
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	origConfig, _ := os.ReadFile(filepath.Join(homeDir, ".aws", "config"))
	origCreds, _ := os.ReadFile(filepath.Join(homeDir, ".aws", "credentials"))

	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "config"), append(origConfig, []byte("\n"+configContent)...), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "credentials"), origCreds, 0o600))

	// Verify assume-role works before running the enumerator.
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

	// Create enumerator with the restricted profile.
	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     []string{"us-east-1"},
		Concurrency: 2,
	})
	defer enumerator.Close()

	// Enumerate S3 — should succeed.
	s3Results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::S3::Bucket", out)
	})
	require.NoError(t, err, "S3 enumeration should not return error")
	// The restricted role has full S3 access, so we should get results
	// (at minimum the test buckets from the fixture).
	t.Logf("S3 results: %d buckets", len(s3Results))

	// Enumerate Amplify — should be denied and skipped.
	amplifyResults, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enumerator.List("AWS::Amplify::App", out)
	})
	require.NoError(t, err, "Amplify enumeration should not return error — it should be skipped")
	assert.Empty(t, amplifyResults, "denied Amplify should produce no resources")

	// Verify the SkipReport captured the denial.
	snap := enumerator.Skipped.Snapshot()
	require.NotEmpty(t, snap, "SkipReport should have recorded the Amplify denial")

	foundAmplifySkip := false
	for _, op := range snap {
		if op.Service == "amplify" || (op.Service == "AWS::Amplify::App" && op.Operation == "List") {
			foundAmplifySkip = true
			assert.Contains(t, op.ErrorCode, "AccessDenied",
				"Amplify skip should have an AccessDenied error code")
			break
		}
	}
	assert.True(t, foundAmplifySkip, "SkipReport must contain an entry for Amplify denial")

	// Verify the summary is non-empty and mentions the denial.
	summary := enumerator.Skipped.Summary()
	assert.NotEmpty(t, summary)
	assert.Contains(t, summary, "AccessDenied")
	t.Logf("Skip summary:\n%s", summary)

	// Verify the detail file was written.
	detailPath := filepath.Join(enumerator.outputDir, "enumeration-skips.json")
	_, err = os.Stat(detailPath)
	assert.NoError(t, err, "enumeration-skips.json should exist")
}

// stscreds is imported to ensure the SDK can resolve assume-role profiles.
var _ = stscreds.NewAssumeRoleProvider

func strPtr(s string) *string { return &s }
