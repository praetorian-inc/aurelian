package outputters

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/konstellation/pkg/graph"
	"github.com/praetorian-inc/konstellation/pkg/graph/adapters"
	"github.com/praetorian-inc/konstellation/pkg/graph/queries"
	"github.com/praetorian-inc/aurelian/internal/message"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// Neo4jGraphOutputter outputs Pure CLI nodes and relationships to Neo4j
type Neo4jGraphOutputter struct {
	*chain.BaseOutputter
	db              graph.GraphDatabase
	ctx             context.Context
	nodes           []any // Pure CLI types (output.CloudResource, output.Risk, etc.)
	relationships   []any // Pure CLI relationship types
	connectionValid bool  // Track if Neo4j connection is available
}


// NewNeo4jGraphOutputter creates a new Neo4j graph outputter
func NewNeo4jGraphOutputter(configs ...cfg.Config) chain.Outputter {
	o := &Neo4jGraphOutputter{
		ctx:             context.Background(),
		nodes:           make([]any, 0),
		relationships:   make([]any, 0),
		connectionValid: false,
	}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

// Params returns the parameters for this outputter
func (o *Neo4jGraphOutputter) Params() []cfg.Param {
	return options.Neo4jOptions()
}

// Initialize is called when the outputter is initialized
func (o *Neo4jGraphOutputter) Initialize() error {
	// Initialize Neo4j connection using updated Konstellation adapter
	graphConfig := &graph.Config{
		URI:      o.Args()[options.Neo4jURI().Name()].(string),
		Username: o.Args()[options.Neo4jUsername().Name()].(string),
		Password: o.Args()[options.Neo4jPassword().Name()].(string),
		Options:  make(map[string]string),
	}

	var err error
	o.db, err = adapters.NewNeo4jDatabase(graphConfig)
	if err != nil {
		message.Warning("Neo4j database connection failed: %v. Neo4j outputter will be disabled.", err)
		o.connectionValid = false
		return nil
	}

	// Verify connectivity
	err = o.db.VerifyConnectivity(o.ctx)
	if err != nil {
		message.Warning("Neo4j connectivity verification failed: %v. Neo4j outputter will be disabled.", err)
		o.connectionValid = false
		return nil
	}

	o.connectionValid = true
	slog.Info("Neo4j graph outputter initialized successfully")
	return nil
}

// Output collects GraphModel nodes and GraphRelationship connections for batch processing
func (o *Neo4jGraphOutputter) Output(v any) error {
	// Skip processing if Neo4j connection is not valid
	if !o.connectionValid {
		slog.Debug("Skipping Neo4j output - connection not available")
		return nil
	}

	slog.Info(fmt.Sprintf("DEBUG: Neo4j outputter received data of type: %T", v))
	switch data := v.(type) {
	case *output.CloudResource:
		o.nodes = append(o.nodes, data)
		slog.Info(fmt.Sprintf("DEBUG: Collected CloudResource node: %s", data.ResourceID))
	case output.CloudResource:
		o.nodes = append(o.nodes, &data)
		slog.Info(fmt.Sprintf("DEBUG: Collected CloudResource node: %s", data.ResourceID))
	case *output.Risk:
		o.nodes = append(o.nodes, data)
		slog.Info(fmt.Sprintf("DEBUG: Collected Risk node: %s", data.Name))
	case output.Risk:
		o.nodes = append(o.nodes, &data)
		slog.Info(fmt.Sprintf("DEBUG: Collected Risk node: %s", data.Name))
	case *types.EnrichedResourceDescription:
		// Convert EnrichedResourceDescription to CloudResource
		cloudResource := &output.CloudResource{
			Platform:     "aws",
			ResourceType: data.TypeName,
			ResourceID:   data.Arn.String(),
			AccountRef:   data.AccountId,
			Region:       data.Region,
			Properties:   make(map[string]any),
		}
		// Copy relevant properties (Identifier is the resource name)
		if data.Identifier != "" {
			cloudResource.Properties["name"] = data.Identifier
		}
		o.nodes = append(o.nodes, cloudResource)
		slog.Info(fmt.Sprintf("DEBUG: Converted ERD to CloudResource: %s", cloudResource.ResourceID))
	case *output.IAMPermission:
		o.relationships = append(o.relationships, data)
		slog.Info(fmt.Sprintf("DEBUG: Collected IAM permission relationship: %s -> %s", data.Source.ID, data.Target.ID))
	case output.IAMPermission:
		o.relationships = append(o.relationships, &data)
		slog.Info(fmt.Sprintf("DEBUG: Collected IAM permission relationship: %s -> %s", data.Source.ID, data.Target.ID))
	case NamedOutputData:
		// Handle wrapped data
		return o.Output(data.Data)
	default:
		// Silently ignore unsupported types
		slog.Info(fmt.Sprintf("DEBUG: Ignoring unsupported type: %T", data))
	}
	return nil
}

// Complete is called when the chain is complete - processes all collected data
func (o *Neo4jGraphOutputter) Complete() error {
	// Skip processing if Neo4j connection is not valid
	if !o.connectionValid || o.db == nil {
		slog.Warn("Skipping Neo4j Complete() - connection not available")
		return nil
	}

	// Convert Pure CLI types to Konstellation types for the adapter
	// Create nodes first
	if len(o.nodes) > 0 {
		graphNodes := make([]*graph.Node, 0, len(o.nodes))
		for _, node := range o.nodes {
			graphNode := o.pureCliNodeToGraphNode(node)
			if graphNode != nil {
				graphNodes = append(graphNodes, graphNode)
			}
		}

		if len(graphNodes) > 0 {
			slog.Info(fmt.Sprintf("Creating %d nodes in Neo4j", len(graphNodes)))
			nodeResult, err := o.db.CreateNodes(o.ctx, graphNodes)
			if err != nil {
				return fmt.Errorf("failed to create nodes: %w", err)
			}
			slog.Info(fmt.Sprintf("Nodes created: %d, updated: %d", nodeResult.NodesCreated, nodeResult.NodesUpdated))
			if len(nodeResult.Errors) > 0 {
				for _, err := range nodeResult.Errors {
					slog.Error(fmt.Sprintf("Node creation error: %s", err.Error()))
				}
			}
		}
	}

	// Create relationships
	if len(o.relationships) > 0 {
		graphRels := make([]*graph.Relationship, 0, len(o.relationships))
		for _, rel := range o.relationships {
			graphRel := o.pureCliRelationshipToGraphRelationship(rel)
			if graphRel != nil {
				graphRels = append(graphRels, graphRel)
			}
		}

		if len(graphRels) > 0 {
			slog.Info(fmt.Sprintf("Creating %d relationships in Neo4j", len(graphRels)))
			relResult, err := o.db.CreateRelationships(o.ctx, graphRels)
			if err != nil {
				return fmt.Errorf("failed to create relationships: %w", err)
			}
			slog.Info(fmt.Sprintf("Relationships created: %d, updated: %d", relResult.RelationshipsCreated, relResult.RelationshipsUpdated))
			if len(relResult.Errors) > 0 {
				for _, err := range relResult.Errors {
					slog.Error(fmt.Sprintf("Relationship creation error: %s", err.Error()))
				}
			}
		}
	}

	// Run AWS enrichment queries (keeping existing functionality)
	if len(o.relationships) > 0 {
		slog.Info("Running AWS enrichment queries")
		eResults, err := queries.EnrichAWS(o.db)
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to enrich AWS data: %s", err.Error()))
		} else {
			slog.Debug(fmt.Sprintf("AWS enrichment completed with %d results", len(eResults)))
		}
	}

	// Run account enrichment (this will be moved from AwsApolloControlFlow)
	err := o.enrichAccountDetails()
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to enrich account details: %s", err.Error()))
	}

	return nil
}

// enrichAccountDetails performs account enrichment queries
// This logic will be moved from AwsApolloControlFlow.enrichAccountDetails()
func (o *Neo4jGraphOutputter) enrichAccountDetails() error {
	// Query for all Account nodes
	query := `
		MATCH (a:Account)
		RETURN a.accountId as accountId
	`

	results, err := o.db.Query(o.ctx, query, nil)
	if err != nil {
		return fmt.Errorf("failed to query Account nodes: %w", err)
	}

	accountCount := 0
	for _, record := range results.Records {
		accountID, ok := record["accountId"]
		if !ok || accountID == nil {
			continue
		}

		accountIDStr, ok := accountID.(string)
		if !ok {
			continue
		}

		// Build properties to update - for now just mark as processed
		// TODO: Add org policies and known account lookup when those are migrated
		props := map[string]interface{}{
			"_enriched": true,
		}

		updateQuery := `
			MATCH (a:Account {accountId: $accountId})
			SET a += $props
			RETURN a
		`

		params := map[string]any{
			"accountId": accountIDStr,
			"props":     props,
		}

		_, err := o.db.Query(o.ctx, updateQuery, params)
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to update Account node for %s: %s", accountIDStr, err.Error()))
		} else {
			accountCount++
		}
	}

	if accountCount > 0 {
		slog.Info(fmt.Sprintf("Enriched %d account nodes", accountCount))
	}

	return nil
}

// Close closes the Neo4j database connection
func (o *Neo4jGraphOutputter) Close() error {
	if o.db != nil {
		return o.db.Close()
	}
	return nil
}

// pureCliNodeToGraphNode converts Pure CLI types to Konstellation graph.Node
func (o *Neo4jGraphOutputter) pureCliNodeToGraphNode(node any) *graph.Node {
	properties := make(map[string]interface{})
	var labels []string
	var uniqueKey []string

	switch n := node.(type) {
	case *output.CloudResource:
		// CloudResource node
		labels = []string{"Resource", n.Platform}
		properties["resourceId"] = n.ResourceID
		properties["resourceType"] = n.ResourceType
		properties["accountId"] = n.AccountRef
		properties["region"] = n.Region
		uniqueKey = []string{"resourceId"}

		// Add custom properties
		if n.Properties != nil {
			for k, v := range n.Properties {
				properties[k] = sanitizeNeo4jProperty(v)
			}
		}

	case *output.Risk:
		// Risk node
		labels = []string{"Risk"}
		properties["name"] = n.Name
		properties["status"] = n.Status
		properties["dns"] = n.DNS
		properties["source"] = n.Source
		if n.Description != "" {
			properties["description"] = n.Description
		}
		uniqueKey = []string{"name", "dns"}

	default:
		slog.Warn(fmt.Sprintf("Unsupported node type for Neo4j: %T", node))
		return nil
	}

	return &graph.Node{
		Labels:     labels,
		Properties: properties,
		UniqueKey:  uniqueKey,
	}
}

// pureCliRelationshipToGraphRelationship converts Pure CLI relationship types to Konstellation graph.Relationship
func (o *Neo4jGraphOutputter) pureCliRelationshipToGraphRelationship(rel any) *graph.Relationship {
	switch r := rel.(type) {
	case *output.IAMPermission:
		// Create nodes from ResourceRefs
		sourceNode := &graph.Node{
			Labels: []string{"Resource", r.Source.Platform},
			Properties: map[string]interface{}{
				"resourceId":   r.Source.ID,
				"resourceType": r.Source.Type,
				"accountId":    r.Source.Account,
			},
			UniqueKey: []string{"resourceId"},
		}

		targetNode := &graph.Node{
			Labels: []string{"Resource", r.Target.Platform},
			Properties: map[string]interface{}{
				"resourceId":   r.Target.ID,
				"resourceType": r.Target.Type,
				"accountId":    r.Target.Account,
			},
			UniqueKey: []string{"resourceId"},
		}

		properties := map[string]interface{}{
			"permission": r.Permission,
			"effect":     r.Effect,
			"capability": r.Capability,
			"timestamp":  r.Timestamp,
		}

		if r.Conditions != nil && len(r.Conditions) > 0 {
			properties["conditions"] = sanitizeNeo4jProperty(r.Conditions)
		}

		return &graph.Relationship{
			StartNode:  sourceNode,
			EndNode:    targetNode,
			Type:       "HAS_PERMISSION",
			Properties: properties,
		}

	default:
		slog.Warn(fmt.Sprintf("Unsupported relationship type for Neo4j: %T", rel))
		return nil
	}
}

// sanitizeNeo4jProperty converts complex types to Neo4j-compatible primitive types
func sanitizeNeo4jProperty(value any) any {
	switch v := value.(type) {
	case []any:
		// Handle arrays - recursively sanitize each element
		sanitized := make([]any, len(v))
		for i, item := range v {
			sanitized[i] = sanitizeNeo4jProperty(item)
		}
		return sanitized
	case map[string]any:
		// Convert maps to JSON strings since Neo4j doesn't support nested maps as properties
		if jsonBytes, err := json.Marshal(v); err == nil {
			return string(jsonBytes)
		}
		// If JSON marshaling fails, return string representation
		return fmt.Sprintf("%+v", v)
	case string, int, int64, float64, bool:
		// Primitive types are supported directly
		return v
	case nil:
		// Handle nil values
		return nil
	default:
		// For any other type, convert to string
		return fmt.Sprintf("%v", v)
	}
}
