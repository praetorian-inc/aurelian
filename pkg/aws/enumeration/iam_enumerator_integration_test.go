//go:build integration

package enumeration

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestIAMEnumerator_Integration(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	opts := plugin.AWSCommonRecon{
		Regions:     []string{"us-east-2"},
		Concurrency: 2,
	}

	t.Run("discovers IAM roles", func(t *testing.T) {
		enumerator := NewEnumerator(opts)
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::IAM::Role", out)
		})
		require.NoError(t, err)
		require.NotEmpty(t, results)

		requireNoDuplicateARNs(t, results)

		roleName := fixture.Output("iam_role_name")
		require.True(t, resultsContainResourceID(results, roleName),
			"expected role name %q in results", roleName)

		roleARN := fixture.Output("iam_role_arn")
		require.True(t, resultsContainARN(results, roleARN),
			"expected role ARN %q in results", roleARN)

		// All results should have Region "global"
		for _, r := range results {
			require.Equal(t, "global", r.Region)
		}
	})

	t.Run("discovers IAM policies", func(t *testing.T) {
		enumerator := NewEnumerator(opts)
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::IAM::Policy", out)
		})
		require.NoError(t, err)
		require.NotEmpty(t, results)

		requireNoDuplicateARNs(t, results)

		policyName := fixture.Output("iam_policy_name")
		require.True(t, resultsContainResourceID(results, policyName),
			"expected policy name %q in results", policyName)

		policyARN := fixture.Output("iam_policy_arn")
		require.True(t, resultsContainARN(results, policyARN),
			"expected policy ARN %q in results", policyARN)
	})

	t.Run("discovers IAM users", func(t *testing.T) {
		enumerator := NewEnumerator(opts)
		results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::IAM::User", out)
		})
		require.NoError(t, err)
		require.NotEmpty(t, results)

		requireNoDuplicateARNs(t, results)

		userName := fixture.Output("iam_user_name")
		require.True(t, resultsContainResourceID(results, userName),
			"expected user name %q in results", userName)

		userARN := fixture.Output("iam_user_arn")
		require.True(t, resultsContainARN(results, userARN),
			"expected user ARN %q in results", userARN)
	})

	t.Run("only enumerates once per lifetime", func(t *testing.T) {
		enumerator := NewEnumerator(opts)

		// First call — should return results
		results1, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::IAM::Role", out)
		})
		require.NoError(t, err)
		require.NotEmpty(t, results1)

		// Second call on same enumerator — sync.Once should prevent re-fetch
		results2, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enumerator.List("AWS::IAM::Role", out)
		})
		require.NoError(t, err)
		require.Empty(t, results2, "second call should produce no results due to sync.Once")
	})
}
