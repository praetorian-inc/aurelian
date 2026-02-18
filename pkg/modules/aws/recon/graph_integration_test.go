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

	// The graph module returns 2 results: entities, iam_relationships
	require.Len(t, results, 2, "graph module should return exactly 2 results")

	var (
		entitiesResult      plugin.Result
		relationshipsResult plugin.Result
	)
	for _, r := range results {
		switch r.Metadata["type"] {
		case "entities":
			entitiesResult = r
		case "iam_relationships":
			relationshipsResult = r
		}
	}

	// Extract entities for sub-tests
	entities, ok := entitiesResult.Data.([]output.AWSIAMResource)
	require.True(t, ok, "entities result should be []output.AWSIAMResource, got %T", entitiesResult.Data)

	// -------------------------------------------------------------------------
	// Result 1: Entities — verify IAM entities appear (from GAAD data)
	// -------------------------------------------------------------------------
	t.Run("GAAD contains created IAM entities", func(t *testing.T) {
		userNames := fixture.OutputList("user_names")
		groupName := fixture.Output("group_name")
		lambdaRoleName := fixture.Output("lambda_role_name")
		assumableRoleName := fixture.Output("assumable_role_name")
		customPolicyARN := fixture.Output("custom_policy_arn")

		// Build lookup maps from entities
		foundUsers := make(map[string]bool)
		foundGroups := make(map[string]bool)
		foundRoles := make(map[string]bool)
		foundPolicyARNs := make(map[string]bool)

		for _, e := range entities {
			switch e.ResourceType {
			case "AWS::IAM::User":
				foundUsers[e.DisplayName] = true
			case "AWS::IAM::Group":
				foundGroups[e.DisplayName] = true
			case "AWS::IAM::Role":
				foundRoles[e.DisplayName] = true
			case "AWS::IAM::Policy":
				foundPolicyARNs[e.ARN] = true
			}
		}

		// Check users
		for _, name := range userNames {
			assert.True(t, foundUsers[name], "entities should contain user %s", name)
		}

		// Check group
		assert.True(t, foundGroups[groupName], "entities should contain group %s", groupName)

		// Check roles
		assert.True(t, foundRoles[lambdaRoleName], "entities should contain role %s", lambdaRoleName)
		assert.True(t, foundRoles[assumableRoleName], "entities should contain role %s", assumableRoleName)

		// Check customer-managed policy
		assert.True(t, foundPolicyARNs[customPolicyARN], "entities should contain policy %s", customPolicyARN)
	})

	// -------------------------------------------------------------------------
	// Result 1 (cont): Entities — verify discovered cloud resources
	// -------------------------------------------------------------------------
	t.Run("Cloud resources contain created resources", func(t *testing.T) {
		// Build ARN and ID sets from non-IAM entities
		arnSet := make(map[string]bool)
		idSet := make(map[string]bool)
		for _, e := range entities {
			arnSet[e.ARN] = true
			idSet[e.ResourceID] = true
		}
		require.True(t, len(entities) > 0, "should have discovered at least some resources")

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
	// Result 2: IAM relationships — verify permission analysis ran
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
		assert.Equal(t, "graph", entitiesResult.Metadata["module"])
		assert.Equal(t, "entities", entitiesResult.Metadata["type"])
		assert.NotEmpty(t, entitiesResult.Metadata["accountID"])

		assert.Equal(t, "graph", relationshipsResult.Metadata["module"])
		assert.Equal(t, "iam_relationships", relationshipsResult.Metadata["type"])

		relCount, ok := relationshipsResult.Metadata["count"].(int)
		if ok {
			assert.Greater(t, relCount, 0, "relationship count should be positive")
		}
	})
}
