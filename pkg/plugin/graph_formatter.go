package plugin

import (
	"context"
	"fmt"
	"log/slog"

	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	awstransformers "github.com/praetorian-inc/aurelian/pkg/graph/transformers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// GraphFormatter formats module results as Neo4j graph
type GraphFormatter struct {
	db     graph.GraphDatabase
	config *graph.Config
}

// NewGraphFormatter creates a new graph formatter with Neo4j connection
func NewGraphFormatter(uri, username, password string) (*GraphFormatter, error) {
	cfg := graph.NewConfig(uri, username, password)
	db, err := adapters.NewNeo4jAdapter(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating Neo4j adapter: %w", err)
	}
	if err := db.VerifyConnectivity(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("Neo4j connection failed: %w", err)
	}
	return &GraphFormatter{db: db, config: cfg}, nil
}

// Format processes module results and writes to Neo4j
func (f *GraphFormatter) Format(results []Result) error {
	ctx := context.Background()

	// Type-switch on Result.Data to identify structure
	var entities []output.AWSIAMResource
	var fullResults []iampkg.FullResult

	for _, result := range results {
		switch data := result.Data.(type) {
		case []output.AWSIAMResource:
			entities = append(entities, data...)
		case []iampkg.FullResult:
			fullResults = data
		}
	}

	if len(entities) == 0 {
		return fmt.Errorf("no entity data found in results")
	}

	// Transform entities to nodes
	var nodes []*graph.Node
	for _, entity := range entities {
		nodes = append(nodes, awstransformers.NodeFromAWSIAMResource(entity))
	}

	// Create nodes in Neo4j
	slog.Info("creating nodes in Neo4j", "count", len(nodes))
	nodeResult, err := f.db.CreateNodes(ctx, nodes)
	if err != nil {
		return fmt.Errorf("creating nodes: %w", err)
	}
	slog.Info("nodes created", "created", nodeResult.NodesCreated, "duration_ms", nodeResult.ExecutionTimeMs)

	// Transform FullResults to relationships
	var relationships []*graph.Relationship
	for _, fr := range fullResults {
		relationships = append(relationships, awstransformers.RelationshipFromFullResult(fr))
	}

	// Create relationships in Neo4j
	slog.Info("creating relationships in Neo4j", "count", len(relationships))
	relResult, err := f.db.CreateRelationships(ctx, relationships)
	if err != nil {
		return fmt.Errorf("creating relationships: %w", err)
	}
	slog.Info("relationships created", "created", relResult.RelationshipsCreated, "duration_ms", relResult.ExecutionTimeMs)

	// Run enrichment queries
	slog.Info("running enrichment queries")
	if err := queries.EnrichAWS(ctx, f.db); err != nil {
		return fmt.Errorf("enrichment queries failed: %w", err)
	}

	// Print summary
	fmt.Println("\n=== Graph Output Summary ===")
	fmt.Printf("Nodes created: %d\n", nodeResult.NodesCreated)
	fmt.Printf("Relationships created: %d\n", relResult.RelationshipsCreated)
	fmt.Printf("Total execution time: %dms\n", nodeResult.ExecutionTimeMs+relResult.ExecutionTimeMs)
	fmt.Println("Graph database: " + f.config.URI)

	return nil
}

// Close releases database resources
func (f *GraphFormatter) Close() error {
	return f.db.Close()
}
