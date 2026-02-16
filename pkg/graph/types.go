package graph

import (
	"context"
)

// Node represents a graph node with labels, properties, and unique key constraint
type Node struct {
	Labels     []string               // e.g., ["Role", "Principal", "AWS::IAM::Role"]
	Properties map[string]interface{} // ARN, metadata, tags
	UniqueKey  []string               // Property names for MERGE identity (e.g., ["arn"])
}

// Relationship represents a directed edge between two nodes
type Relationship struct {
	Type       string                 // e.g., "CAN_PRIVESC", "STS_ASSUMEROLE"
	Properties map[string]interface{} // method, requires, capability
	StartNode  *Node                  // Source node
	EndNode    *Node                  // Target node
}

// BatchResult contains statistics from batch operations
type BatchResult struct {
	NodesCreated         int
	RelationshipsCreated int
	PropertiesSet        int
	ConstraintsCreated   int
	ExecutionTimeMs      int64
}

// QueryResult contains rows returned from a Cypher query
type QueryResult struct {
	Records []map[string]interface{} // Each record is a map of column -> value
	Summary QuerySummary
}

// QuerySummary contains counters from query execution
type QuerySummary struct {
	NodesCreated         int
	RelationshipsCreated int
	PropertiesSet        int
}

// GraphDatabase defines the interface for graph database operations
// Implementations: Neo4j adapter (pkg/graph/adapters/neo4j.go)
type GraphDatabase interface {
	// CreateNodes performs batch MERGE operations for nodes
	// Groups nodes by labels+uniqueKeys for efficiency
	CreateNodes(ctx context.Context, nodes []*Node) (*BatchResult, error)

	// CreateRelationships performs batch MERGE operations for relationships
	// Automatically creates nodes if they don't exist
	CreateRelationships(ctx context.Context, rels []*Relationship) (*BatchResult, error)

	// Query executes raw Cypher query with parameters
	Query(ctx context.Context, cypher string, params map[string]any) (*QueryResult, error)

	// VerifyConnectivity tests the database connection
	VerifyConnectivity(ctx context.Context) error

	// Close releases database resources
	Close() error
}
