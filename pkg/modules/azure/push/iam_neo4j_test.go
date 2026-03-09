package push

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	azuretransform "github.com/praetorian-inc/aurelian/pkg/graph/transformers/azure"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// Integration test that pushes collected IAM data to Neo4j.
// Requires:
//   - NEO4J_URI env var (e.g., bolt://localhost:7687)
//   - AZURE_IAM_DATA_FILE env var pointing to consolidated IAM JSON
//
// Run with:
//
//	NEO4J_URI=bolt://localhost:7687 AZURE_IAM_DATA_FILE=path/to/data.json \
//	  go test ./pkg/modules/azure/push/ -run TestIntegration -v -count=1 -timeout 10m

func skipUnlessNeo4j(t *testing.T) (string, string) {
	t.Helper()
	uri := os.Getenv("NEO4J_URI")
	dataFile := os.Getenv("AZURE_IAM_DATA_FILE")
	if uri == "" || dataFile == "" {
		t.Skip("NEO4J_URI and/or AZURE_IAM_DATA_FILE not set, skipping integration test")
	}
	return uri, dataFile
}

func TestIntegration_PushToNeo4j(t *testing.T) {
	uri, dataFile := skipUnlessNeo4j(t)
	ctx := context.Background()

	// Load data
	raw, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatalf("reading data file: %v", err)
	}

	var data types.AzureIAMConsolidated
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("parsing data file: %v", err)
	}

	t.Logf("Loaded data:")
	if data.EntraID != nil {
		t.Logf("  Users: %d, Groups: %d, SPs: %d, Apps: %d",
			data.EntraID.Users.Len(), data.EntraID.Groups.Len(),
			data.EntraID.ServicePrincipals.Len(), data.EntraID.Applications.Len())
	}

	// Connect to Neo4j
	user := os.Getenv("NEO4J_USER")
	if user == "" {
		user = "neo4j"
	}
	pass := os.Getenv("NEO4J_PASSWORD")
	if pass == "" {
		pass = "password"
	}

	db, err := adapters.NewNeo4jAdapter(graph.NewConfig(uri, user, pass))
	if err != nil {
		t.Fatalf("connecting to Neo4j: %v", err)
	}
	defer db.Close()

	if err := db.VerifyConnectivity(ctx); err != nil {
		t.Fatalf("Neo4j connectivity failed: %v", err)
	}
	t.Log("Neo4j connected")

	// Clear DB
	if _, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil); err != nil {
		t.Fatalf("clearing database: %v", err)
	}
	t.Log("Database cleared")

	// Transform
	nodes, rels := azuretransform.TransformAll(&data)
	t.Logf("Transformed: %d nodes, %d relationships", len(nodes), len(rels))

	// Push nodes
	if len(nodes) > 0 {
		nodeResult, err := db.CreateNodes(ctx, nodes)
		if err != nil {
			t.Fatalf("creating nodes: %v", err)
		}
		t.Logf("Nodes: created=%d, propertiesSet=%d, durationMs=%d",
			nodeResult.NodesCreated, nodeResult.PropertiesSet, nodeResult.ExecutionTimeMs)
	}

	// Push relationships
	if len(rels) > 0 {
		relResult, err := db.CreateRelationships(ctx, rels)
		if err != nil {
			t.Fatalf("creating relationships: %v", err)
		}
		t.Logf("Relationships: created=%d, propertiesSet=%d, durationMs=%d",
			relResult.RelationshipsCreated, relResult.PropertiesSet, relResult.ExecutionTimeMs)
	}

	// Run enrichment
	if err := queries.EnrichAzure(ctx, db); err != nil {
		t.Logf("WARNING: enrichment failed: %v", err)
	} else {
		t.Log("Enrichment queries complete")
	}

	// Validate: count nodes by label
	validateQuery := func(label string) int {
		result, err := db.Query(ctx, "MATCH (n:"+label+") RETURN count(n) AS c", nil)
		if err != nil {
			t.Logf("WARNING: count query for %s failed: %v", label, err)
			return -1
		}
		if len(result.Records) > 0 {
			if c, ok := result.Records[0]["c"].(int64); ok {
				return int(c)
			}
		}
		return 0
	}

	t.Log("Node counts in Neo4j:")
	for _, label := range []string{"User", "Group", "ServicePrincipal", "Application",
		"Device", "DirectoryRole", "RoleDefinition", "ManagementGroup",
		"Subscription", "RBACRoleDefinition"} {
		count := validateQuery(label)
		t.Logf("  %-25s %d", label, count)
	}

	// Validate: count relationships by type
	relCountQuery := func(relType string) int {
		result, err := db.Query(ctx, "MATCH ()-[r:"+relType+"]->() RETURN count(r) AS c", nil)
		if err != nil {
			t.Logf("WARNING: count query for %s failed: %v", relType, err)
			return -1
		}
		if len(result.Records) > 0 {
			if c, ok := result.Records[0]["c"].(int64); ok {
				return int(c)
			}
		}
		return 0
	}

	t.Log("Relationship counts in Neo4j:")
	for _, relType := range []string{"MEMBER_OF", "HAS_ROLE", "OWNS", "HAS_APP_ROLE",
		"HAS_OAUTH2_GRANT", "HAS_RBAC_ROLE", "CONTAINS", "HAS_PIM_ROLE", "ELIGIBLE_FOR_PIM_ROLE"} {
		count := relCountQuery(relType)
		t.Logf("  %-25s %d", relType, count)
	}
}
