package adapters

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/praetorian-inc/aurelian/pkg/graph"
)

// Neo4jAdapter implements graph.GraphDatabase using the official Neo4j Go driver
type Neo4jAdapter struct {
	driver    neo4j.DriverWithContext
	batchSize int
}

// NewNeo4jAdapter creates a new Neo4j adapter with the given configuration
func NewNeo4jAdapter(cfg *graph.Config) (*Neo4jAdapter, error) {
	if cfg.URI == "" {
		return nil, fmt.Errorf("Neo4j URI is required")
	}

	driver, err := neo4j.NewDriverWithContext(
		cfg.URI,
		neo4j.BasicAuth(cfg.Username, cfg.Password, ""),
	)
	if err != nil {
		return nil, fmt.Errorf("creating Neo4j driver: %w", err)
	}

	return &Neo4jAdapter{
		driver:    driver,
		batchSize: 1000,
	}, nil
}

// escapeLabel wraps labels containing special characters in backticks for Cypher
func escapeLabel(label string) string {
	if strings.ContainsAny(label, ".:- /") {
		return "`" + label + "`"
	}
	return label
}

// VerifyConnectivity tests the database connection by running a simple query
func (a *Neo4jAdapter) VerifyConnectivity(ctx context.Context) error {
	session := a.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	_, err := session.Run(ctx, "RETURN 1 AS test", nil)
	if err != nil {
		return fmt.Errorf("verifying Neo4j connectivity: %w", err)
	}

	return nil
}

// CreateNodes performs batch MERGE operations for nodes
// Groups nodes by labels+uniqueKeys for efficient batch processing
func (a *Neo4jAdapter) CreateNodes(ctx context.Context, nodes []*graph.Node) (*graph.BatchResult, error) {
	if len(nodes) == 0 {
		return &graph.BatchResult{}, nil
	}

	startTime := time.Now()
	result := &graph.BatchResult{}

	// Group nodes by labels and unique keys for batching
	type nodeKey struct {
		labels    string
		uniqueKey string
	}
	groups := make(map[nodeKey][]*graph.Node)

	for _, node := range nodes {
		key := nodeKey{
			labels:    fmt.Sprint(node.Labels),
			uniqueKey: fmt.Sprint(node.UniqueKey),
		}
		groups[key] = append(groups[key], node)
	}

	// Process each group in batches
	session := a.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	for _, group := range groups {
		if len(group) == 0 {
			continue
		}

		// Process in batches of batchSize
		for i := 0; i < len(group); i += a.batchSize {
			end := i + a.batchSize
			if end > len(group) {
				end = len(group)
			}
			batch := group[i:end]

			// Build UNWIND/MERGE query
			firstNode := batch[0]
			cypher := a.buildNodeMergeQuery(firstNode)

			// Prepare batch data
			batchData := make([]map[string]interface{}, len(batch))
			for j, node := range batch {
				batchData[j] = node.Properties
			}

			// Execute batch
			summary, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
				res, err := tx.Run(ctx, cypher, map[string]interface{}{
					"nodes": batchData,
				})
				if err != nil {
					return nil, err
				}
				return res.Consume(ctx)
			})

			if err != nil {
				return nil, fmt.Errorf("executing node merge batch: %w", err)
			}

			if resultSummary, ok := summary.(neo4j.ResultSummary); ok {
				counters := resultSummary.Counters()
				result.NodesCreated += counters.NodesCreated()
				result.PropertiesSet += counters.PropertiesSet()
				result.ConstraintsCreated += counters.ConstraintsAdded()
			}
		}
	}

	result.ExecutionTimeMs = time.Since(startTime).Milliseconds()
	return result, nil
}

// buildNodeMergeQuery constructs a Cypher MERGE query for a node group
func (a *Neo4jAdapter) buildNodeMergeQuery(node *graph.Node) string {
	// Build labels string
	labels := ""
	for _, label := range node.Labels {
		labels += ":" + escapeLabel(label)
	}

	// Build MERGE pattern with unique key properties
	mergeProps := make(map[string]bool)
	for _, key := range node.UniqueKey {
		mergeProps[key] = true
	}

	cypher := "UNWIND $nodes AS node\nMERGE (n" + labels + " {"
	first := true
	for _, key := range node.UniqueKey {
		if !first {
			cypher += ", "
		}
		cypher += key + ": node." + key
		first = false
	}
	cypher += "})\n"

	// SET all other properties
	cypher += "SET n += node\n"
	cypher += "RETURN count(n) AS count"

	return cypher
}

// nodeDeduplicationKey creates a unique key for node deduplication that includes
// property values, not just property names. Without values, all nodes of the same
// type collapse to one entry.
func nodeDeduplicationKey(n *graph.Node) string {
	vals := make([]string, len(n.UniqueKey))
	for i, k := range n.UniqueKey {
		vals[i] = fmt.Sprint(n.Properties[k])
	}
	return fmt.Sprintf("%v-%v", n.Labels, vals)
}

// CreateRelationships performs batch MERGE operations for relationships
// Ensures nodes exist first, then creates relationships
// Groups relationships by {startLabels, startUniqueKey, endLabels, endUniqueKey, relType}
// so each batch uses a single Cypher template that matches all items in the batch.
func (a *Neo4jAdapter) CreateRelationships(ctx context.Context, rels []*graph.Relationship) (*graph.BatchResult, error) {
	if len(rels) == 0 {
		return &graph.BatchResult{}, nil
	}

	startTime := time.Now()
	result := &graph.BatchResult{}

	// First ensure all nodes exist
	uniqueNodes := make(map[string]*graph.Node)
	for _, rel := range rels {
		if rel.StartNode != nil {
			key := nodeDeduplicationKey(rel.StartNode)
			uniqueNodes[key] = rel.StartNode
		}
		if rel.EndNode != nil {
			key := nodeDeduplicationKey(rel.EndNode)
			uniqueNodes[key] = rel.EndNode
		}
	}

	nodes := make([]*graph.Node, 0, len(uniqueNodes))
	for _, node := range uniqueNodes {
		nodes = append(nodes, node)
	}

	nodeResult, err := a.CreateNodes(ctx, nodes)
	if err != nil {
		return nil, fmt.Errorf("creating nodes for relationships: %w", err)
	}
	result.NodesCreated = nodeResult.NodesCreated
	result.PropertiesSet = nodeResult.PropertiesSet

	// Group relationships by structure so each batch uses a matching Cypher template.
	// Without grouping, batch[0]'s labels/type would be used for all items, causing
	// mismatched relationships to silently fail their MATCH clauses.
	type relKey struct {
		startLabels    string
		startUniqueKey string
		endLabels      string
		endUniqueKey   string
		relType        string
	}
	groups := make(map[relKey][]*graph.Relationship)

	for _, rel := range rels {
		key := relKey{
			startLabels:    fmt.Sprint(rel.StartNode.Labels),
			startUniqueKey: fmt.Sprint(rel.StartNode.UniqueKey),
			endLabels:      fmt.Sprint(rel.EndNode.Labels),
			endUniqueKey:   fmt.Sprint(rel.EndNode.UniqueKey),
			relType:        rel.Type,
		}
		groups[key] = append(groups[key], rel)
	}

	// Now create relationships in batches per group
	session := a.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	for _, group := range groups {
		if len(group) == 0 {
			continue
		}

		// Process each group in batches of batchSize
		for i := 0; i < len(group); i += a.batchSize {
			end := i + a.batchSize
			if end > len(group) {
				end = len(group)
			}
			batch := group[i:end]

			// Prepare batch data (no need for labels/keys — they're in the Cypher template)
			batchData := make([]map[string]interface{}, len(batch))
			for j, rel := range batch {
				batchData[j] = map[string]interface{}{
					"startProps": rel.StartNode.Properties,
					"endProps":   rel.EndNode.Properties,
					"relProps":   rel.Properties,
				}
			}

			// Build and execute relationship MERGE (safe: all items share same structure)
			cypher := a.buildRelationshipMergeQuery(batch[0])

			summary, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
				res, err := tx.Run(ctx, cypher, map[string]interface{}{
					"rels": batchData,
				})
				if err != nil {
					return nil, err
				}
				return res.Consume(ctx)
			})

			if err != nil {
				return nil, fmt.Errorf("executing relationship merge batch: %w", err)
			}

			if resultSummary, ok := summary.(neo4j.ResultSummary); ok {
				counters := resultSummary.Counters()
				result.RelationshipsCreated += counters.RelationshipsCreated()
				result.PropertiesSet += counters.PropertiesSet()
			}
		}
	}

	result.ExecutionTimeMs = time.Since(startTime).Milliseconds()
	return result, nil
}

// buildRelationshipMergeQuery constructs a Cypher MERGE query for relationships
func (a *Neo4jAdapter) buildRelationshipMergeQuery(rel *graph.Relationship) string {
	// Build start node labels
	startLabels := ""
	for _, label := range rel.StartNode.Labels {
		startLabels += ":" + escapeLabel(label)
	}

	// Build end node labels
	endLabels := ""
	for _, label := range rel.EndNode.Labels {
		endLabels += ":" + escapeLabel(label)
	}

	// Build MATCH patterns for start and end nodes
	cypher := "UNWIND $rels AS rel\n"
	cypher += "MATCH (start" + startLabels + " {"

	// Add start node unique key match
	first := true
	for _, key := range rel.StartNode.UniqueKey {
		if !first {
			cypher += ", "
		}
		cypher += key + ": rel.startProps." + key
		first = false
	}
	cypher += "})\n"

	cypher += "MATCH (end" + endLabels + " {"

	// Add end node unique key match
	first = true
	for _, key := range rel.EndNode.UniqueKey {
		if !first {
			cypher += ", "
		}
		cypher += key + ": rel.endProps." + key
		first = false
	}
	cypher += "})\n"

	// MERGE the relationship
	cypher += "MERGE (start)-[r:" + rel.Type + "]->(end)\n"
	cypher += "SET r += rel.relProps\n"
	cypher += "RETURN count(r) AS count"

	return cypher
}

// Query executes a raw Cypher query with parameters
func (a *Neo4jAdapter) Query(ctx context.Context, cypher string, params map[string]any) (*graph.QueryResult, error) {
	session := a.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	result, err := session.Run(ctx, cypher, params)
	if err != nil {
		return nil, fmt.Errorf("executing query: %w", err)
	}

	records := make([]map[string]interface{}, 0)
	for result.Next(ctx) {
		record := result.Record()
		recordMap := make(map[string]interface{})
		for _, key := range record.Keys {
			value, ok := record.Get(key)
			if ok {
				recordMap[key] = value
			}
		}
		records = append(records, recordMap)
	}

	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("iterating results: %w", err)
	}

	summary, err := result.Consume(ctx)
	if err != nil {
		return nil, fmt.Errorf("consuming result: %w", err)
	}

	counters := summary.Counters()
	return &graph.QueryResult{
		Records: records,
		Summary: graph.QuerySummary{
			NodesCreated:         counters.NodesCreated(),
			RelationshipsCreated: counters.RelationshipsCreated(),
			PropertiesSet:        counters.PropertiesSet(),
		},
	}, nil
}

// Close releases database resources
func (a *Neo4jAdapter) Close() error {
	if a.driver != nil {
		ctx := context.Background()
		if err := a.driver.Close(ctx); err != nil {
			return fmt.Errorf("closing Neo4j driver: %w", err)
		}
	}
	return nil
}
