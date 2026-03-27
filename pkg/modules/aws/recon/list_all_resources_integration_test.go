//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSList(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	t.Run("Amplify apps", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		if !ok {
			t.Skip("list-all module not registered in plugin system")
		}

		results, err := testutil.RunAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::Amplify::App"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		testutil.AssertMinResults(t, results, 1)
		testutil.AssertNoDuplicateResults(t, results)
		testutil.AssertResultContainsString(t, results, fixture.Output("amplify_app_id"))

		// Verify enricher populated branch URLs
		found := false
		for _, r := range results {
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), fixture.Output("amplify_app_id")) {
				assert.Contains(t, string(b), "amplifyapp.com", "should contain default domain URL")
				found = true
				break
			}
		}
		assert.True(t, found, "should find Amplify app in results")
	})

	t.Run("EC2 instances", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		if !ok {
			t.Skip("list-all module not registered in plugin system")
		}

		results, err := testutil.RunAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		testutil.AssertMinResults(t, results, 1)
		testutil.AssertNoDuplicateResults(t, results)

		for _, id := range fixture.OutputList("instance_ids") {
			testutil.AssertResultContainsString(t, results, id)
		}
	})

	t.Run("S3 buckets", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		if !ok {
			t.Skip("list-all module not registered in plugin system")
		}

		results, err := testutil.RunAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::S3::Bucket"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		testutil.AssertMinResults(t, results, 1)
		testutil.AssertNoDuplicateResults(t, results)

		for _, name := range fixture.OutputList("bucket_names") {
			testutil.AssertResultContainsString(t, results, name)
		}
	})

	t.Run("Lambda functions", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		if !ok {
			t.Skip("list-all module not registered in plugin system")
		}

		results, err := testutil.RunAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::Lambda::Function"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		testutil.AssertMinResults(t, results, 1)
		testutil.AssertNoDuplicateResults(t, results)

		for _, arn := range fixture.OutputList("function_arns") {
			testutil.AssertResultContainsARN(t, results, arn)
		}
	})

	t.Run("IAM roles", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		if !ok {
			t.Skip("list-all module not registered in plugin system")
		}

		results, err := testutil.RunAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::IAM::Role"},
				"regions":       []string{"us-east-1", "us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		testutil.AssertMinResults(t, results, 1)
		testutil.AssertNoDuplicateResults(t, results)
		testutil.AssertResultContainsString(t, results, fixture.Output("iam_role_name"))
		testutil.AssertResultContainsARN(t, results, fixture.Output("iam_role_arn"))
	})

	t.Run("IAM policies", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		if !ok {
			t.Skip("list-all module not registered in plugin system")
		}

		results, err := testutil.RunAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::IAM::Policy"},
				"regions":       []string{"us-east-1", "us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		testutil.AssertMinResults(t, results, 1)
		testutil.AssertNoDuplicateResults(t, results)
		testutil.AssertResultContainsString(t, results, fixture.Output("iam_policy_name"))
		testutil.AssertResultContainsARN(t, results, fixture.Output("iam_policy_arn"))
	})

	t.Run("IAM users", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		if !ok {
			t.Skip("list-all module not registered in plugin system")
		}

		results, err := testutil.RunAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::IAM::User"},
				"regions":       []string{"us-east-1", "us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		testutil.AssertMinResults(t, results, 1)
		testutil.AssertNoDuplicateResults(t, results)
		testutil.AssertResultContainsString(t, results, fixture.Output("iam_user_name"))
		testutil.AssertResultContainsARN(t, results, fixture.Output("iam_user_arn"))
	})
}
