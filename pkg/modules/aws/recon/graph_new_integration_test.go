//go:build integration

package recon

import (
	"context"
	"sort"
	"testing"

	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSGraphNew(t *testing.T) {
	t.Setenv("AWS_PROFILE", "aurelian")
	fixture := testutil.NewFixture(t, "aws/recon/graph")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph-new")
	if !ok {
		t.Fatal("graph-new module not registered in plugin system")
	}

	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-2"},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	require.Len(t, results, 2, "graph-new module should return exactly 2 results")

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
			case "AWS::IAM::ManagedPolicy":
				foundPolicyARNs[e.ARN] = true
			}
		}

		for _, name := range userNames {
			assert.True(t, foundUsers[name], "entities should contain user %s", name)
		}
		assert.True(t, foundGroups[groupName], "entities should contain group %s", groupName)
		assert.True(t, foundRoles[lambdaRoleName], "entities should contain role %s", lambdaRoleName)
		assert.True(t, foundRoles[assumableRoleName], "entities should contain role %s", assumableRoleName)
		assert.True(t, foundPolicyARNs[customPolicyARN], "entities should contain policy %s", customPolicyARN)
	})

	// -------------------------------------------------------------------------
	// Result 1 (cont): Entities — verify discovered cloud resources
	// -------------------------------------------------------------------------
	t.Run("Cloud resources contain created resources", func(t *testing.T) {
		arnSet := make(map[string]bool)
		idSet := make(map[string]bool)
		for _, e := range entities {
			arnSet[e.ARN] = true
			idSet[e.ResourceID] = true
		}
		require.True(t, len(entities) > 0, "should have discovered at least some resources")

		bucketName := fixture.Output("s3_bucket_name")
		assert.True(t, idSet[bucketName] || arnSet[fixture.Output("s3_bucket_arn")],
			"resources should contain S3 bucket %s", bucketName)

		sqsARN := fixture.Output("sqs_queue_arn")
		assert.True(t, arnSet[sqsARN], "resources should contain SQS queue %s", sqsARN)

		snsARN := fixture.Output("sns_topic_arn")
		assert.True(t, arnSet[snsARN], "resources should contain SNS topic %s", snsARN)

		lambdaARN := fixture.Output("lambda_function_arn")
		assert.True(t, arnSet[lambdaARN], "resources should contain Lambda function %s", lambdaARN)
	})

	// -------------------------------------------------------------------------
	// Result 2: IAM relationships — verify permission analysis ran
	// -------------------------------------------------------------------------
	t.Run("IAM relationships are produced", func(t *testing.T) {
		relationships, ok := relationshipsResult.Data.([]output.AWSIAMRelationship)
		require.True(t, ok, "relationships result should be []output.AWSIAMRelationship, got %T", relationshipsResult.Data)
		require.NotEmpty(t, relationships, "should have at least some IAM relationships")

		principalARNs := make(map[string]int)
		for _, rel := range relationships {
			principalARNs[rel.Principal.ARN]++
		}

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

		t.Logf("Total IAM relationships: %d, unique principals: %d", len(relationships), len(principalARNs))
	})

	// -------------------------------------------------------------------------
	// Result metadata validation
	// -------------------------------------------------------------------------
	t.Run("Result metadata is correct", func(t *testing.T) {
		assert.Equal(t, "graph-new", entitiesResult.Metadata["module"])
		assert.Equal(t, "entities", entitiesResult.Metadata["type"])
		assert.NotEmpty(t, entitiesResult.Metadata["accountID"])

		assert.Equal(t, "graph-new", relationshipsResult.Metadata["module"])
		assert.Equal(t, "iam_relationships", relationshipsResult.Metadata["type"])

		relCount, ok := relationshipsResult.Metadata["count"].(int)
		if ok {
			assert.Greater(t, relCount, 0, "relationship count should be positive")
		}
	})
}

// TestAWSGraphNewVsOld runs both the old and new graph modules against the same
// AWS account and verifies that the new module discovers everything the old one did.
func TestAWSGraphNewVsOld(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/graph")
	fixture.Setup()

	cfg := plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-2"},
		},
		Context: context.Background(),
	}

	// Run old module
	oldMod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph")
	require.True(t, ok, "graph module not registered")
	oldResults, err := oldMod.Run(cfg)
	require.NoError(t, err)
	require.Len(t, oldResults, 2)

	// Run new module
	newMod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph-new")
	require.True(t, ok, "graph-new module not registered")
	newResults, err := newMod.Run(cfg)
	require.NoError(t, err)
	require.Len(t, newResults, 2)

	// -------------------------------------------------------------------------
	// Extract results by type
	// -------------------------------------------------------------------------
	getResult := func(results []plugin.Result, typ string) plugin.Result {
		for _, r := range results {
			if r.Metadata["type"] == typ {
				return r
			}
		}
		t.Fatalf("no result with type %q", typ)
		return plugin.Result{}
	}

	oldEntities := getResult(oldResults, "entities").Data.([]output.AWSIAMResource)
	newEntities := getResult(newResults, "entities").Data.([]output.AWSIAMResource)
	oldRels := getResult(oldResults, "iam_relationships").Data.([]iampkg.FullResult)
	newRels := getResult(newResults, "iam_relationships").Data.([]output.AWSIAMRelationship)

	// -------------------------------------------------------------------------
	// Entities: new module should have every ARN the old module found
	// -------------------------------------------------------------------------
	t.Run("Entity ARN coverage", func(t *testing.T) {
		oldARNs := make(map[string]bool, len(oldEntities))
		for _, e := range oldEntities {
			oldARNs[e.ARN] = true
		}
		newARNs := make(map[string]bool, len(newEntities))
		for _, e := range newEntities {
			newARNs[e.ARN] = true
		}

		var missing []string
		for arn := range oldARNs {
			if !newARNs[arn] {
				missing = append(missing, arn)
			}
		}
		sort.Strings(missing)
		assert.Empty(t, missing, "new module is missing %d entity ARNs that old module found", len(missing))

		t.Logf("Old entities: %d, New entities: %d", len(oldEntities), len(newEntities))
	})

	// -------------------------------------------------------------------------
	// Relationships: new module should cover every (principal, resource, action)
	// triple the old module found.
	// -------------------------------------------------------------------------
	t.Run("Relationship coverage", func(t *testing.T) {
		type triple struct {
			principalARN string
			resourceARN  string
			action       string
		}

		// Build set from old FullResults
		oldSet := make(map[triple]bool, len(oldRels))
		for _, fr := range oldRels {
			var principalARN string
			switch p := fr.Principal.(type) {
			case *types.UserDetail:
				principalARN = p.Arn
			case *types.RoleDetail:
				principalARN = p.Arn
			case *types.GroupDetail:
				principalARN = p.Arn
			case string:
				principalARN = p
			}
			resourceARN := ""
			if fr.Resource != nil {
				resourceARN = fr.Resource.Arn.String()
			}
			oldSet[triple{principalARN, resourceARN, fr.Action}] = true
		}

		// Build set from new AWSIAMRelationships
		newSet := make(map[triple]bool, len(newRels))
		for _, rel := range newRels {
			newSet[triple{rel.Principal.ARN, rel.Resource.ARN, rel.Action}] = true
		}

		var missing []triple
		for tri := range oldSet {
			if !newSet[tri] {
				missing = append(missing, tri)
			}
		}

		// Log some examples if there are missing triples
		if len(missing) > 0 {
			limit := 20
			if len(missing) < limit {
				limit = len(missing)
			}
			for _, m := range missing[:limit] {
				t.Logf("MISSING: principal=%s resource=%s action=%s", m.principalARN, m.resourceARN, m.action)
			}
		}

		assert.True(t, len(missing) == 0,
			"new module is missing %d relationship triples that old module found (out of %d old, %d new)",
			len(missing), len(oldSet), len(newSet))
	})
}
