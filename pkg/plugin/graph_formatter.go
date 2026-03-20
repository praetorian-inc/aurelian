package plugin

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	awstransformers "github.com/praetorian-inc/aurelian/pkg/graph/transformers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// GraphFormatter formats module results as Neo4j graph.
// Supports both batch (Format) and streaming (Send/Flush/Finalize) modes.
type GraphFormatter struct {
	db     graph.GraphDatabase
	config *graph.Config

	// Streaming buffers
	pendingNodes []*graph.Node
	pendingRels  []*graph.Relationship
	flushSize    int

	// Running totals for summary
	totalNodesCreated int
	totalRelsCreated  int
	totalTimeMs       int64
}

// NewGraphFormatter creates a new graph formatter with Neo4j connection
func NewGraphFormatter(uri, username, password string) (*GraphFormatter, error) {
	cfg := graph.NewConfig(uri, username, password)
	db, err := adapters.NewNeo4jAdapter(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating Neo4j adapter: %w", err)
	}
	if err := db.VerifyConnectivity(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("Neo4j connection failed: %w", err)
	}
	return &GraphFormatter{db: db, config: cfg, flushSize: 1000}, nil
}

// Format processes module results and writes to Neo4j
func (f *GraphFormatter) Format(results []model.AurelianModel) error {
	ctx := context.Background()

	// Collect entities and relationships from individual emitted models.
	var entities []output.AWSIAMResource
	var iamRelationships []output.AWSIAMRelationship

	for _, result := range results {
		switch data := result.(type) {
		case output.AWSIAMResource:
			entities = append(entities, data)
		case output.AWSIAMRelationship:
			iamRelationships = append(iamRelationships, data)
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

	// Transform AWSIAMRelationships to graph relationships
	var relationships []*graph.Relationship
	for _, rel := range iamRelationships {
		relationships = append(relationships, awstransformers.RelationshipFromAWSIAMRelationship(rel))
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

// Send buffers a single model for streaming ingestion. When the buffer reaches
// flushSize, it is automatically flushed to Neo4j. Non-graph types are ignored.
func (f *GraphFormatter) Send(m model.AurelianModel) error {
	switch data := m.(type) {
	case output.AWSIAMResource:
		f.pendingNodes = append(f.pendingNodes, awstransformers.NodeFromAWSIAMResource(data))
	case output.AWSIAMRelationship:
		f.pendingRels = append(f.pendingRels, awstransformers.RelationshipFromAWSIAMRelationship(data))
	}

	if len(f.pendingNodes)+len(f.pendingRels) >= f.flushSize {
		return f.Flush()
	}
	return nil
}

// Flush writes all buffered nodes and relationships to Neo4j, then clears the buffers.
func (f *GraphFormatter) Flush() error {
	ctx := context.Background()

	if len(f.pendingNodes) > 0 {
		res, err := f.db.CreateNodes(ctx, f.pendingNodes)
		if err != nil {
			return fmt.Errorf("creating nodes: %w", err)
		}
		f.totalNodesCreated += res.NodesCreated
		f.totalTimeMs += res.ExecutionTimeMs
		f.pendingNodes = f.pendingNodes[:0]
	}

	if len(f.pendingRels) > 0 {
		res, err := f.db.CreateRelationships(ctx, f.pendingRels)
		if err != nil {
			return fmt.Errorf("creating relationships: %w", err)
		}
		f.totalRelsCreated += res.RelationshipsCreated
		f.totalTimeMs += res.ExecutionTimeMs
		f.pendingRels = f.pendingRels[:0]
	}

	return nil
}

// Finalize flushes remaining buffered data, runs enrichment queries, and prints a summary.
func (f *GraphFormatter) Finalize() error {
	if err := f.Flush(); err != nil {
		return err
	}

	ctx := context.Background()
	slog.Info("running enrichment queries")
	if err := queries.EnrichAWS(ctx, f.db); err != nil {
		return fmt.Errorf("enrichment queries failed: %w", err)
	}

	fmt.Println("\n=== Graph Output Summary ===")
	fmt.Printf("Nodes created: %d\n", f.totalNodesCreated)
	fmt.Printf("Relationships created: %d\n", f.totalRelsCreated)
	fmt.Printf("Total execution time: %dms\n", f.totalTimeMs)
	fmt.Println("Graph database: " + f.config.URI)

	return nil
}

// Close releases database resources
func (f *GraphFormatter) Close() error {
	return f.db.Close()
}
