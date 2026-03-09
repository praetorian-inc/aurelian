package push

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	azuretransform "github.com/praetorian-inc/aurelian/pkg/graph/transformers/azure"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() { plugin.Register(&AzureIAMPushModule{}) }

// IAMPushConfig holds parameters for the Azure IAM Neo4j push module.
type IAMPushConfig struct {
	plugin.GraphOutputBase
	DataFile string `param:"data-file" desc:"Path to consolidated IAM JSON file (from iam-pull module)" required:"true"`
	ClearDB  bool   `param:"clear-db" desc:"Clear all nodes and relationships before import" default:"false"`
	Enrich   bool   `param:"enrich" desc:"Run enrichment queries after import" default:"true"`
}

// AzureIAMPushModule pushes consolidated Azure IAM data to Neo4j.
type AzureIAMPushModule struct {
	IAMPushConfig
}

func (m *AzureIAMPushModule) ID() string                { return "iam-push" }
func (m *AzureIAMPushModule) Name() string              { return "Azure IAM Push (Neo4j)" }
func (m *AzureIAMPushModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureIAMPushModule) Category() plugin.Category { return plugin.CategoryPush }
func (m *AzureIAMPushModule) OpsecLevel() string        { return "none" }
func (m *AzureIAMPushModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureIAMPushModule) Description() string {
	return "Pushes consolidated Azure IAM data (from iam-pull) to Neo4j. " +
		"Transforms Entra ID, PIM, RBAC, and Management Group data into graph nodes and relationships, " +
		"then runs enrichment queries for privilege escalation detection."
}

func (m *AzureIAMPushModule) References() []string {
	return []string{
		"https://neo4j.com/docs/cypher-manual/current/clauses/merge/",
	}
}

func (m *AzureIAMPushModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.EntraID/users",
		"Microsoft.EntraID/groups",
		"Microsoft.EntraID/servicePrincipals",
		"Microsoft.EntraID/applications",
		"Microsoft.Authorization/roleAssignments",
		"Microsoft.Authorization/roleDefinitions",
		"Microsoft.Management/managementGroups",
	}
}

func (m *AzureIAMPushModule) Parameters() any { return &m.IAMPushConfig }

func (m *AzureIAMPushModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := context.Background()

	// 1. Load consolidated IAM data from file
	slog.Info("loading IAM data", "file", m.DataFile)
	data, err := loadConsolidatedData(m.DataFile)
	if err != nil {
		return fmt.Errorf("loading data file: %w", err)
	}
	logDataSummary(data)

	// 2. Connect to Neo4j
	slog.Info("connecting to Neo4j", "uri", m.Neo4jURI)
	db, err := adapters.NewNeo4jAdapter(graph.NewConfig(m.Neo4jURI, m.Neo4jUsername, m.Neo4jPassword))
	if err != nil {
		return fmt.Errorf("connecting to Neo4j: %w", err)
	}
	defer db.Close()

	if err := db.VerifyConnectivity(ctx); err != nil {
		return fmt.Errorf("Neo4j connectivity check failed: %w", err)
	}
	slog.Info("Neo4j connection verified")

	// 3. Optionally clear the database
	if m.ClearDB {
		slog.Info("clearing database")
		if _, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil); err != nil {
			return fmt.Errorf("clearing database: %w", err)
		}
		slog.Info("database cleared")
	}

	// 4. Create constraints and indexes for performance
	slog.Info("creating constraints and indexes")
	constraints := []string{
		"CREATE CONSTRAINT IF NOT EXISTS FOR (n:User) REQUIRE n.id IS UNIQUE",
		"CREATE CONSTRAINT IF NOT EXISTS FOR (n:Group) REQUIRE n.id IS UNIQUE",
		"CREATE CONSTRAINT IF NOT EXISTS FOR (n:ServicePrincipal) REQUIRE n.id IS UNIQUE",
		"CREATE CONSTRAINT IF NOT EXISTS FOR (n:Application) REQUIRE n.id IS UNIQUE",
		"CREATE CONSTRAINT IF NOT EXISTS FOR (n:RoleDefinition) REQUIRE n.id IS UNIQUE",
		"CREATE CONSTRAINT IF NOT EXISTS FOR (n:ManagementGroup) REQUIRE n.id IS UNIQUE",
		"CREATE CONSTRAINT IF NOT EXISTS FOR (n:Subscription) REQUIRE n.id IS UNIQUE",
	}
	for _, c := range constraints {
		if _, err := db.Query(ctx, c, nil); err != nil {
			slog.Warn("constraint creation failed (may already exist)", "error", err)
		}
	}

	// 5. Transform to graph nodes and relationships
	slog.Info("transforming IAM data to graph model")
	nodes, rels := azuretransform.TransformAll(data)
	slog.Info("transformation complete", "nodes", len(nodes), "relationships", len(rels))

	// 6. Push nodes
	if len(nodes) > 0 {
		slog.Info("creating nodes", "count", len(nodes))
		nodeResult, err := db.CreateNodes(ctx, nodes)
		if err != nil {
			return fmt.Errorf("creating nodes: %w", err)
		}
		slog.Info("nodes created",
			"nodesCreated", nodeResult.NodesCreated,
			"propertiesSet", nodeResult.PropertiesSet,
			"durationMs", nodeResult.ExecutionTimeMs)
	}

	// 7. Push relationships
	if len(rels) > 0 {
		slog.Info("creating relationships", "count", len(rels))
		relResult, err := db.CreateRelationships(ctx, rels)
		if err != nil {
			return fmt.Errorf("creating relationships: %w", err)
		}
		slog.Info("relationships created",
			"relationshipsCreated", relResult.RelationshipsCreated,
			"propertiesSet", relResult.PropertiesSet,
			"durationMs", relResult.ExecutionTimeMs)
	}

	// 8. Run enrichment queries
	if m.Enrich {
		slog.Info("running enrichment queries")
		if err := queries.EnrichAzure(ctx, db); err != nil {
			slog.Warn("enrichment queries failed", "error", err)
		} else {
			slog.Info("enrichment queries complete")
		}
	}

	slog.Info("Azure IAM push complete",
		"totalNodes", len(nodes),
		"totalRelationships", len(rels))

	return nil
}

// loadConsolidatedData reads and deserializes an AzureIAMConsolidated JSON file.
func loadConsolidatedData(path string) (*types.AzureIAMConsolidated, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var consolidated types.AzureIAMConsolidated
	if err := json.Unmarshal(data, &consolidated); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &consolidated, nil
}

// logDataSummary logs a summary of the loaded consolidated data.
func logDataSummary(data *types.AzureIAMConsolidated) {
	if data.EntraID != nil {
		slog.Info("Entra ID data loaded",
			"users", data.EntraID.Users.Len(),
			"groups", data.EntraID.Groups.Len(),
			"servicePrincipals", data.EntraID.ServicePrincipals.Len(),
			"applications", data.EntraID.Applications.Len())
	}
	if data.PIM != nil {
		slog.Info("PIM data loaded",
			"activeAssignments", len(data.PIM.ActiveAssignments),
			"eligibleAssignments", len(data.PIM.EligibleAssignments))
	}
	if data.RBAC != nil {
		slog.Info("RBAC data loaded", "subscriptions", len(data.RBAC))
	}
	if data.ManagementGroups != nil {
		slog.Info("Management Groups data loaded",
			"groups", len(data.ManagementGroups.Groups),
			"relationships", len(data.ManagementGroups.Relationships))
	}
}
