//go:build integration

package queries_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testBoltURL string
var testCleanup func()

func TestMain(m *testing.M) {
	ctx := context.Background()
	var err error
	testBoltURL, testCleanup, err = testutil.StartNeo4jContainer(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start Neo4j: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	testCleanup()
	os.Exit(code)
}

// newTestDB creates a fresh Neo4j adapter using the shared test container URL.
func newTestDB(t *testing.T) graph.GraphDatabase {
	t.Helper()
	cfg := graph.NewConfig(testBoltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// setupFixture creates a minimal graph:
//   - 3 Principals: alice, bob, eve (each with Arn property)
//   - alice has IAM_CREATEPOLICYVERSION permission on bob (direct target)
//   - alice does NOT have that permission on eve
//
// After running method_01, there should be exactly 1 CAN_PRIVESC edge:
//
//	alice -> bob (NOT alice -> eve)
//
// This verifies the Cartesian product fix: old code would create alice->bob AND alice->eve.
func setupFixture(t *testing.T, ctx context.Context, db graph.GraphDatabase) {
	t.Helper()

	cypherSetup := `
    CREATE (alice:Principal {Arn: 'arn:aws:iam::111111111111:user/alice', name: 'alice'})
    CREATE (bob:Principal {Arn: 'arn:aws:iam::111111111111:user/bob', name: 'bob'})
    CREATE (eve:Principal {Arn: 'arn:aws:iam::111111111111:user/eve', name: 'eve'})
    CREATE (alice)-[:IAM_CREATEPOLICYVERSION]->(bob)
    `
	_, err := db.Query(ctx, cypherSetup, nil)
	require.NoError(t, err, "fixture setup failed")
}

// setupFixtureLowercaseArn creates principals with lowercase 'arn' property
// to verify the coalesce(target.Arn, target.arn) pattern works.
func setupFixtureLowercaseArn(t *testing.T, ctx context.Context, db graph.GraphDatabase) {
	t.Helper()

	cypherSetup := `
    CREATE (alice:Principal {arn: 'arn:aws:iam::111111111111:user/alice', name: 'alice'})
    CREATE (bob:Principal {arn: 'arn:aws:iam::111111111111:user/bob', name: 'bob'})
    CREATE (alice)-[:IAM_CREATEPOLICYVERSION]->(bob)
    `
	_, err := db.Query(ctx, cypherSetup, nil)
	require.NoError(t, err, "lowercase arn fixture setup failed")
}

// setupDualPermFixture creates the graph for method 39 testing:
//   - alice has LAMBDA_UPDATEFUNCTIONCODE on lambdaFunc
//   - alice has LAMBDA_INVOKEFUNCTION on lambdaFunc
//   - alice has LAMBDA_UPDATEFUNCTIONCODE on otherFunc (but NOT invoke)
//
// After method_39: alice -> lambdaFunc only (requires BOTH permissions on SAME target).
func setupDualPermFixture(t *testing.T, ctx context.Context, db graph.GraphDatabase) {
	t.Helper()

	cypherSetup := `
    CREATE (alice:Principal {Arn: 'arn:aws:iam::111111111111:user/alice', name: 'alice'})
    CREATE (lambdaFunc:Resource {Arn: 'arn:aws:lambda:us-east-1:111111111111:function:target', name: 'target'})
    CREATE (otherFunc:Resource {Arn: 'arn:aws:lambda:us-east-1:111111111111:function:other', name: 'other'})
    CREATE (alice)-[:LAMBDA_UPDATEFUNCTIONCODE]->(lambdaFunc)
    CREATE (alice)-[:LAMBDA_INVOKEFUNCTION]->(lambdaFunc)
    CREATE (alice)-[:LAMBDA_UPDATEFUNCTIONCODE]->(otherFunc)
    `
	_, err := db.Query(ctx, cypherSetup, nil)
	require.NoError(t, err, "dual-perm fixture setup failed")
}

func TestPrivescIntegration_SinglePermission_NoCartesian(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	testutil.ClearNeo4jDatabase(t, testBoltURL)
	setupFixture(t, ctx, db)

	// Run method_01 query
	query, exists := queries.GetQuery("aws/enrich/privesc/method_01")
	require.True(t, exists)

	_, err := db.Query(ctx, query.Cypher, nil)
	require.NoError(t, err)

	// Count CAN_PRIVESC edges
	result, err := db.Query(ctx, `
        MATCH (a)-[pe:CAN_PRIVESC]->(b)
        RETURN a.name AS attacker, b.name AS target, pe.method AS method
    `, nil)
	require.NoError(t, err)

	// Should have exactly 1 edge: alice -> bob
	require.Len(t, result.Records, 1,
		"expected exactly 1 CAN_PRIVESC edge, got %d (Cartesian product if >1)", len(result.Records))

	record := result.Records[0]
	assert.Equal(t, "alice", record["attacker"])
	assert.Equal(t, "bob", record["target"])
	assert.Equal(t, "iam:CreatePolicyVersion", record["method"])
}

func TestPrivescIntegration_CoalesceHandlesLowercaseArn(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	testutil.ClearNeo4jDatabase(t, testBoltURL)
	setupFixtureLowercaseArn(t, ctx, db)

	query, exists := queries.GetQuery("aws/enrich/privesc/method_01")
	require.True(t, exists)

	_, err := db.Query(ctx, query.Cypher, nil)
	require.NoError(t, err)

	// With lowercase 'arn', coalesce should still filter self-edges
	result, err := db.Query(ctx, `
        MATCH (a)-[pe:CAN_PRIVESC]->(b)
        RETURN a.name AS attacker, b.name AS target
    `, nil)
	require.NoError(t, err)

	require.Len(t, result.Records, 1, "coalesce should handle lowercase arn")
	assert.Equal(t, "alice", result.Records[0]["attacker"])
	assert.Equal(t, "bob", result.Records[0]["target"])
}

func TestPrivescIntegration_SelfEdgeExcluded(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	testutil.ClearNeo4jDatabase(t, testBoltURL)

	// alice has permission on herself (self-referencing)
	_, err := db.Query(ctx, `
        CREATE (alice:Principal {Arn: 'arn:aws:iam::111111111111:user/alice', name: 'alice'})
        CREATE (alice)-[:IAM_CREATEPOLICYVERSION]->(alice)
    `, nil)
	require.NoError(t, err)

	query, exists := queries.GetQuery("aws/enrich/privesc/method_01")
	require.True(t, exists)

	_, err = db.Query(ctx, query.Cypher, nil)
	require.NoError(t, err)

	result, err := db.Query(ctx, `MATCH ()-[pe:CAN_PRIVESC]->() RETURN count(pe) AS cnt`, nil)
	require.NoError(t, err)

	// Self-edge should be excluded by the coalesce guard
	cnt := result.Records[0]["cnt"]
	assert.Equal(t, int64(0), cnt, "self-edges must be excluded by coalesce guard")
}

func TestPrivescIntegration_Method39_DualPermission(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	testutil.ClearNeo4jDatabase(t, testBoltURL)
	setupDualPermFixture(t, ctx, db)

	query, exists := queries.GetQuery("aws/enrich/privesc/method_39")
	require.True(t, exists)

	_, err := db.Query(ctx, query.Cypher, nil)
	require.NoError(t, err)

	result, err := db.Query(ctx, `
        MATCH (a)-[pe:CAN_PRIVESC]->(b)
        RETURN a.name AS attacker, b.name AS target, pe.method AS method
    `, nil)
	require.NoError(t, err)

	// Only lambdaFunc has BOTH permissions; otherFunc only has updateCode
	require.Len(t, result.Records, 1,
		"method 39 should create edge only when BOTH permissions exist on same target")

	assert.Equal(t, "alice", result.Records[0]["attacker"])
	assert.Equal(t, "target", result.Records[0]["target"])
	assert.Contains(t, result.Records[0]["method"], "lambda:UpdateFunctionCode")
}

func TestPrivescIntegration_SampledMethods(t *testing.T) {
	// Sample one method from each permission category to verify
	// the fix works across different relationship types.
	samples := []struct {
		queryID     string
		relType     string // The relationship type to create in fixture
		description string
	}{
		{"aws/enrich/privesc/method_06", "IAM_ATTACHUSERPOLICY", "attach user policy"},
		{"aws/enrich/privesc/method_09", "IAM_PUTUSERPOLICY", "put user policy"},
		{"aws/enrich/privesc/method_12", "IAM_ADDUSERTOGROUP", "add user to group"},
		{"aws/enrich/privesc/method_22", "STS_ASSUMEROLE", "STS assume role"},
		{"aws/enrich/privesc/method_23", "SSM_SENDCOMMAND", "SSM send command"},
		{"aws/enrich/privesc/method_27", "CODEBUILD_CREATEPROJECT", "CodeBuild create project"},
	}

	ctx := context.Background()
	db := newTestDB(t)

	for _, s := range samples {
		t.Run(s.description, func(t *testing.T) {
			testutil.ClearNeo4jDatabase(t, testBoltURL)

			// Seed: alice -> bob with the specific permission, eve is a bystander
			setup := fmt.Sprintf(`
                CREATE (alice:Principal {Arn: 'arn:aws:iam::111111111111:user/alice', name: 'alice'})
                CREATE (bob:Principal {Arn: 'arn:aws:iam::111111111111:user/bob', name: 'bob'})
                CREATE (eve:Principal {Arn: 'arn:aws:iam::111111111111:user/eve', name: 'eve'})
                CREATE (alice)-[:%s]->(bob)
            `, s.relType)

			_, err := db.Query(ctx, setup, nil)
			require.NoError(t, err)

			query, exists := queries.GetQuery(s.queryID)
			require.True(t, exists)

			_, err = db.Query(ctx, query.Cypher, nil)
			require.NoError(t, err)

			result, err := db.Query(ctx, `
                MATCH (a)-[pe:CAN_PRIVESC]->(b)
                RETURN a.name AS attacker, b.name AS target
            `, nil)
			require.NoError(t, err)

			require.Len(t, result.Records, 1,
				"%s: expected 1 CAN_PRIVESC edge, got %d", s.description, len(result.Records))
			assert.Equal(t, "alice", result.Records[0]["attacker"])
			assert.Equal(t, "bob", result.Records[0]["target"],
				"%s: edge should point to bob (actual target), not eve (bystander)", s.description)
		})
	}
}
