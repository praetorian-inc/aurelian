//go:build integration

package recon

import (
	"context"
	"testing"

	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSGraph(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/graph")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph")
	if !ok {
		t.Fatal("graph module not registered in plugin system")
	}

	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-2"},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)

	// The graph module returns 3 results: gaad, resources, iam_relationships
	require.Len(t, results, 3, "graph module should return exactly 3 results")

	var (
		gaadResult          plugin.Result
		resourcesResult     plugin.Result
		relationshipsResult plugin.Result
	)
	for _, r := range results {
		switch r.Metadata["type"] {
		case "gaad":
			gaadResult = r
		case "resources":
			resourcesResult = r
		case "iam_relationships":
			relationshipsResult = r
		}
	}

	// -------------------------------------------------------------------------
	// Result 1: GAAD — verify IAM entities appear
	// -------------------------------------------------------------------------
	t.Run("GAAD contains created IAM entities", func(t *testing.T) {
		gaadData, ok := gaadResult.Data.(*iampkg.Gaad)
		require.True(t, ok, "gaad result should be *iam.Gaad, got %T", gaadResult.Data)

		userNames := fixture.OutputList("user_names")
		groupName := fixture.Output("group_name")
		lambdaRoleName := fixture.Output("lambda_role_name")
		assumableRoleName := fixture.Output("assumable_role_name")
		customPolicyARN := fixture.Output("custom_policy_arn")

		// Check users
		foundUsers := make(map[string]bool)
		for _, u := range gaadData.UserDetailList {
			foundUsers[u.UserName] = true
		}
		for _, name := range userNames {
			assert.True(t, foundUsers[name], "GAAD should contain user %s", name)
		}

		// Check group
		foundGroup := false
		for _, g := range gaadData.GroupDetailList {
			if g.GroupName == groupName {
				foundGroup = true
				break
			}
		}
		assert.True(t, foundGroup, "GAAD should contain group %s", groupName)

		// Check roles
		foundRoles := make(map[string]bool)
		for _, r := range gaadData.RoleDetailList {
			foundRoles[r.RoleName] = true
		}
		assert.True(t, foundRoles[lambdaRoleName], "GAAD should contain role %s", lambdaRoleName)
		assert.True(t, foundRoles[assumableRoleName], "GAAD should contain role %s", assumableRoleName)

		// Check customer-managed policy
		foundPolicy := false
		for _, p := range gaadData.Policies {
			if p.Arn == customPolicyARN {
				foundPolicy = true
				break
			}
		}
		assert.True(t, foundPolicy, "GAAD should contain policy %s", customPolicyARN)
	})

	// -------------------------------------------------------------------------
	// Result 2: Cloud resources — verify discovered resources
	// -------------------------------------------------------------------------
	t.Run("Cloud resources contain created resources", func(t *testing.T) {
		resourceMap, ok := resourcesResult.Data.(map[string][]output.CloudResource)
		require.True(t, ok, "resources result should be map[string][]CloudResource, got %T", resourcesResult.Data)

		// Flatten all resources to check for our test resources
		var allResources []output.CloudResource
		for _, resources := range resourceMap {
			allResources = append(allResources, resources...)
		}
		require.NotEmpty(t, allResources, "should have discovered at least some resources")

		// Build ARN set for easy lookup
		arnSet := make(map[string]bool)
		idSet := make(map[string]bool)
		for _, r := range allResources {
			arnSet[r.ARN] = true
			idSet[r.ResourceID] = true
		}

		// S3 bucket
		bucketName := fixture.Output("s3_bucket_name")
		assert.True(t, idSet[bucketName] || arnSet[fixture.Output("s3_bucket_arn")],
			"resources should contain S3 bucket %s", bucketName)

		// SQS queue
		sqsARN := fixture.Output("sqs_queue_arn")
		assert.True(t, arnSet[sqsARN], "resources should contain SQS queue %s", sqsARN)

		// SNS topic
		snsARN := fixture.Output("sns_topic_arn")
		assert.True(t, arnSet[snsARN], "resources should contain SNS topic %s", snsARN)

		// Lambda function
		lambdaARN := fixture.Output("lambda_function_arn")
		assert.True(t, arnSet[lambdaARN], "resources should contain Lambda function %s", lambdaARN)
	})

	// -------------------------------------------------------------------------
	// Result 3: IAM relationships — verify permission analysis ran
	// -------------------------------------------------------------------------
	t.Run("IAM relationships are produced", func(t *testing.T) {
		fullResults, ok := relationshipsResult.Data.([]iampkg.FullResult)
		require.True(t, ok, "relationships result should be []iam.FullResult, got %T", relationshipsResult.Data)
		require.NotEmpty(t, fullResults, "should have at least some IAM relationships")

		// Collect all principal ARNs from the results by type-switching on the
		// concrete types stored in FullResult.Principal.
		principalARNs := make(map[string]int)
		for _, fr := range fullResults {
			var arn string
			switch p := fr.Principal.(type) {
			case *iampkg.UserDL:
				arn = p.Arn
			case *iampkg.RoleDL:
				arn = p.Arn
			case *iampkg.GroupDL:
				arn = p.Arn
			case string:
				arn = p
			}
			if arn != "" {
				principalARNs[arn]++
			}
		}

		// Verify our test user with ReadOnlyAccess appears — it should have
		// many allowed actions against the enumerated resources.
		userARNs := fixture.OutputList("user_arns")
		foundAnyUser := false
		for _, userARN := range userARNs {
			if count, ok := principalARNs[userARN]; ok {
				t.Logf("Found user %s with %d relationships", userARN, count)
				foundAnyUser = true
			}
		}
		assert.True(t, foundAnyUser,
			"IAM relationships should reference at least one test user; found principals: %d unique", len(principalARNs))

		t.Logf("Total IAM relationships: %d, unique principals: %d", len(fullResults), len(principalARNs))
	})

	// -------------------------------------------------------------------------
	// Result metadata validation
	// -------------------------------------------------------------------------
	t.Run("Result metadata is correct", func(t *testing.T) {
		assert.Equal(t, "graph", gaadResult.Metadata["module"])
		assert.Equal(t, "gaad", gaadResult.Metadata["type"])
		assert.NotEmpty(t, gaadResult.Metadata["accountID"])

		assert.Equal(t, "graph", resourcesResult.Metadata["module"])
		assert.Equal(t, "resources", resourcesResult.Metadata["type"])

		assert.Equal(t, "graph", relationshipsResult.Metadata["module"])
		assert.Equal(t, "iam_relationships", relationshipsResult.Metadata["type"])

		relCount, ok := relationshipsResult.Metadata["count"].(int)
		if ok {
			assert.Greater(t, relCount, 0, "relationship count should be positive")
		}
	})
}

