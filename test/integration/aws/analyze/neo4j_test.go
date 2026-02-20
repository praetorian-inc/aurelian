//go:build integration

package analyze

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNeo4jAdapter_CreateNodes verifies that the Neo4j adapter can create nodes
// and returns accurate counts
func TestNeo4jAdapter_CreateNodes(t *testing.T) {
	ctx := context.Background()
	require.NotEmpty(t, sharedNeo4jBoltURL, "shared Neo4j container not available")
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)

	cfg := graph.NewConfig(sharedNeo4jBoltURL, "", "")
	adapter, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	defer adapter.Close()

	// Verify connectivity
	err = adapter.VerifyConnectivity(ctx)
	require.NoError(t, err)

	// Create 2 test nodes
	nodes := []*graph.Node{
		{
			Labels: []string{"TestUser", "Principal"},
			Properties: map[string]interface{}{
				"Arn":      "arn:aws:iam::123456789012:user/alice",
				"UserName": "alice",
				"UserId":   "AIDAI23456789EXAMPLE",
			},
			UniqueKey: []string{"Arn"},
		},
		{
			Labels: []string{"TestRole", "Principal"},
			Properties: map[string]interface{}{
				"Arn":      "arn:aws:iam::123456789012:role/test-role",
				"RoleName": "test-role",
				"RoleId":   "AROAI23456789EXAMPLE",
			},
			UniqueKey: []string{"Arn"},
		},
	}

	result, err := adapter.CreateNodes(ctx, nodes)
	require.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated, "expected 2 nodes created")
	assert.Greater(t, result.PropertiesSet, 0, "expected properties set")
	assert.Greater(t, result.ExecutionTimeMs, int64(0), "expected positive execution time")

	// Verify nodes exist via query
	queryResult, err := adapter.Query(ctx, "MATCH (n) RETURN count(n) as nodeCount", nil)
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 1)
	nodeCount, ok := queryResult.Records[0]["nodeCount"].(int64)
	require.True(t, ok, "nodeCount should be int64")
	assert.Equal(t, int64(2), nodeCount, "expected 2 nodes in database")
}

// TestNeo4jAdapter_CreateRelationships verifies that relationships can be created
// with automatic node creation
func TestNeo4jAdapter_CreateRelationships(t *testing.T) {
	ctx := context.Background()
	require.NotEmpty(t, sharedNeo4jBoltURL, "shared Neo4j container not available")
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)

	cfg := graph.NewConfig(sharedNeo4jBoltURL, "", "")
	adapter, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	defer adapter.Close()

	// Create relationship with auto-node creation
	rels := []*graph.Relationship{
		{
			Type: "MEMBER_OF",
			Properties: map[string]interface{}{
				"via": "direct",
			},
			StartNode: &graph.Node{
				Labels: []string{"TestUser", "Principal"},
				Properties: map[string]interface{}{
					"Arn":      "arn:aws:iam::123456789012:user/bob",
					"UserName": "bob",
				},
				UniqueKey: []string{"Arn"},
			},
			EndNode: &graph.Node{
				Labels: []string{"TestGroup", "Principal"},
				Properties: map[string]interface{}{
					"Arn":       "arn:aws:iam::123456789012:group/developers",
					"GroupName": "developers",
				},
				UniqueKey: []string{"Arn"},
			},
		},
	}

	result, err := adapter.CreateRelationships(ctx, rels)
	require.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated, "expected 2 nodes auto-created")
	assert.Equal(t, 1, result.RelationshipsCreated, "expected 1 relationship created")

	// Verify relationship exists
	queryResult, err := adapter.Query(ctx,
		"MATCH ()-[r:MEMBER_OF]->() RETURN count(r) as relCount",
		nil,
	)
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 1)
	relCount, ok := queryResult.Records[0]["relCount"].(int64)
	require.True(t, ok, "relCount should be int64")
	assert.Equal(t, int64(1), relCount, "expected 1 relationship in database")
}

// TestGraphFormatter_FullPipeline tests the complete GraphFormatter flow with
// mock GAAD data, resources, and FullResults
func TestGraphFormatter_FullPipeline(t *testing.T) {
	ctx := context.Background()
	require.NotEmpty(t, sharedNeo4jBoltURL, "shared Neo4j container not available")
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)

	// Create GraphFormatter
	formatter, err := plugin.NewGraphFormatter(sharedNeo4jBoltURL, "", "")
	require.NoError(t, err)
	defer formatter.Close()

	// Create mock AWSIAMResources with OriginalData for GAAD types
	user := types.UserDetail{
		Arn:      "arn:aws:iam::123456789012:user/charlie",
		UserName: "charlie",
		UserId:   "AIDAI12345EXAMPLE",
	}
	role := types.RoleDetail{
		Arn:      "arn:aws:iam::123456789012:role/admin-role",
		RoleName: "admin-role",
		RoleId:   "AROAI12345EXAMPLE",
	}
	group := types.GroupDetail{
		Arn:       "arn:aws:iam::123456789012:group/admins",
		GroupName: "admins",
		GroupId:   "AGPAI12345EXAMPLE",
	}

	entities := []output.AWSIAMResource{
		{
			AWSResource: output.AWSResource{
				ARN:          "arn:aws:iam::123456789012:user/charlie",
				ResourceType: "AWS::IAM::User",
				ResourceID:   "arn:aws:iam::123456789012:user/charlie",
				AccountRef:   "123456789012",
			},
			OriginalData: user,
		},
		{
			AWSResource: output.AWSResource{
				ARN:          "arn:aws:iam::123456789012:role/admin-role",
				ResourceType: "AWS::IAM::Role",
				ResourceID:   "arn:aws:iam::123456789012:role/admin-role",
				AccountRef:   "123456789012",
			},
			OriginalData: role,
		},
		{
			AWSResource: output.AWSResource{
				ARN:          "arn:aws:iam::123456789012:group/admins",
				ResourceType: "AWS::IAM::Group",
				ResourceID:   "arn:aws:iam::123456789012:group/admins",
				AccountRef:   "123456789012",
			},
			OriginalData: group,
		},
		{
			AWSResource: output.AWSResource{
				ARN:          "arn:aws:s3:::test-bucket-123",
				ResourceType: "AWS::S3::Bucket",
				ResourceID:   "arn:aws:s3:::test-bucket-123",
				Region:       "us-east-1",
				AccountRef:   "123456789012",
				Properties: map[string]interface{}{
					"BucketName": "test-bucket-123",
				},
			},
		},
	}

	// Create mock FullResult (privilege escalation relationship)
	targetArn, _ := arn.Parse("arn:aws:iam::123456789012:role/admin-role")
	fullResults := []iampkg.FullResult{
		{
			Principal: &types.UserDetail{
				Arn:      "arn:aws:iam::123456789012:user/charlie",
				UserName: "charlie",
				UserId:   "AIDAI12345EXAMPLE",
			},
			Resource: &types.EnrichedResourceDescription{
				Identifier: "admin-role",
				TypeName:   "AWS::IAM::Role",
				Region:     "us-east-1",
				AccountId:  "123456789012",
				Arn:        targetArn,
			},
			Action: "iam:PassRole",
			Result: &iampkg.EvaluationResult{Allowed: true},
		},
	}

	// Convert GAAD and AWSResources to []output.AWSIAMResource (the type GraphFormatter expects)
	entities := iampkg.FromGAAD(gaad, "123456789012")
	for _, res := range resources {
		entities = append(entities, output.FromAWSResource(res))
	}

	// Create Results array
	results := []plugin.Result{
		{Data: entities},
		{Data: fullResults},
	}

	// Format to graph
	err = formatter.Format(results)
	require.NoError(t, err)

	// Verify graph structure via adapter query
	cfg := graph.NewConfig(sharedNeo4jBoltURL, "", "")
	adapter, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	defer adapter.Close()

	// Count principals (user + role + group)
	queryResult, err := adapter.Query(ctx,
		"MATCH (n:Principal) RETURN count(n) as principalCount",
		nil,
	)
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 1)
	principalCount, ok := queryResult.Records[0]["principalCount"].(int64)
	require.True(t, ok, "principalCount should be int64")
	assert.Equal(t, int64(3), principalCount, "expected 3 principals (user, role, group)")

	// Count resources
	queryResult, err = adapter.Query(ctx,
		"MATCH (n:Resource) RETURN count(n) as resourceCount",
		nil,
	)
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 1)
	resourceCount, ok := queryResult.Records[0]["resourceCount"].(int64)
	require.True(t, ok, "resourceCount should be int64")
	assert.GreaterOrEqual(t, resourceCount, int64(1), "expected at least 1 resource (S3 bucket + relationship targets)")

	// Verify privilege escalation relationship exists
	queryResult, err = adapter.Query(ctx,
		"MATCH ()-[r]->() RETURN count(r) as relCount",
		nil,
	)
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 1)
	relCount, ok := queryResult.Records[0]["relCount"].(int64)
	require.True(t, ok, "relCount should be int64")
	assert.Greater(t, relCount, int64(0), "expected at least 1 relationship")
}

// TestEnrichmentQueries verifies that enrichment queries can be loaded and executed
func TestEnrichmentQueries(t *testing.T) {
	ctx := context.Background()
	require.NotEmpty(t, sharedNeo4jBoltURL, "shared Neo4j container not available")
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)

	cfg := graph.NewConfig(sharedNeo4jBoltURL, "", "")
	adapter, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	defer adapter.Close()

	// Create test nodes for enrichment
	nodes := []*graph.Node{
		{
			Labels: []string{"TestUser", "Principal"},
			Properties: map[string]interface{}{
				"Arn":      "arn:aws:iam::123456789012:user/test-user",
				"UserName": "test-user",
			},
			UniqueKey: []string{"Arn"},
		},
		{
			Labels: []string{"TestRole", "Principal"},
			Properties: map[string]interface{}{
				"Arn":      "arn:aws:iam::123456789012:role/test-role",
				"RoleName": "test-role",
			},
			UniqueKey: []string{"Arn"},
		},
	}

	_, err = adapter.CreateNodes(ctx, nodes)
	require.NoError(t, err)

	// Run enrichment queries
	err = queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err, "EnrichAWS should complete without error")

	// Verify query registry loaded queries
	queryList := queries.ListQueries()
	assert.Greater(t, len(queryList), 0, "expected at least one enrichment query loaded")
}
