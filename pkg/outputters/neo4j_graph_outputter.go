package outputters

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/konstellation/pkg/graph"
	"github.com/praetorian-inc/konstellation/pkg/graph/adapters"
	"github.com/praetorian-inc/konstellation/pkg/graph/queries"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// Neo4jGraphOutputter outputs GraphModel nodes and GraphRelationship connections to Neo4j
type Neo4jGraphOutputter struct {
	*chain.BaseOutputter
	db            graph.GraphDatabase
	ctx           context.Context
	nodes         []model.GraphModel
	relationships []model.GraphRelationship
}

// NewNeo4jGraphOutputter creates a new Neo4j graph outputter
func NewNeo4jGraphOutputter(configs ...cfg.Config) chain.Outputter {
	o := &Neo4jGraphOutputter{
		ctx:           context.Background(),
		nodes:         make([]model.GraphModel, 0),
		relationships: make([]model.GraphRelationship, 0),
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
		return fmt.Errorf("failed to create Neo4j database connection: %w", err)
	}

	// Verify connectivity
	err = o.db.VerifyConnectivity(o.ctx)
	if err != nil {
		return fmt.Errorf("failed to verify Neo4j connectivity: %w", err)
	}

	o.Logger.Info("Neo4j graph outputter initialized successfully")
	return nil
}

// Output collects GraphModel nodes and GraphRelationship connections for batch processing
func (o *Neo4jGraphOutputter) Output(v any) error {
	switch data := v.(type) {
	case model.GraphModel:
		o.nodes = append(o.nodes, data)
		o.Logger.Debug(fmt.Sprintf("Collected node: %s (labels: %v)", data.GetKey(), data.GetLabels()))
	case *model.AWSResource:
		o.nodes = append(o.nodes, data)
		o.Logger.Debug(fmt.Sprintf("Collected AWS resource: %s", data.Name))
	case model.GraphRelationship:
		o.relationships = append(o.relationships, data)
		o.Logger.Debug(fmt.Sprintf("Collected relationship: %s", data.Label()))
	case model.File:
		// Handle proof files - extract attack path information if it's a proof file
		if strings.Contains(data.Name, "proofs/") {
			o.Logger.Debug(fmt.Sprintf("Collected proof file: %s", data.Name))
			// The proof content is stored in data.Bytes and contains the record.String() formatted attack path
			// For now, we just log it - actual proof processing would be done by other outputters
		}
	case NamedOutputData:
		// Handle wrapped data
		return o.Output(data.Data)
	default:
		// Silently ignore unsupported types
		o.Logger.Debug(fmt.Sprintf("Ignoring unsupported type: %T", data))
	}
	return nil
}

// Complete is called when the chain is complete - processes all collected data
func (o *Neo4jGraphOutputter) Complete() error {
	if o.db == nil {
		return fmt.Errorf("Neo4j database not initialized")
	}

	// Convert Tabularium types to Konstellation types for the adapter
	// Create nodes first
	if len(o.nodes) > 0 {
		graphNodes := make([]*graph.Node, len(o.nodes))
		for i, node := range o.nodes {
			graphNodes[i] = o.tabullariumNodeToGraphNode(node)
		}

		o.Logger.Info(fmt.Sprintf("Creating %d nodes in Neo4j", len(graphNodes)))
		nodeResult, err := o.db.CreateNodes(o.ctx, graphNodes)
		if err != nil {
			return fmt.Errorf("failed to create nodes: %w", err)
		}
		o.Logger.Info(fmt.Sprintf("Nodes created: %d, updated: %d", nodeResult.NodesCreated, nodeResult.NodesUpdated))
		if len(nodeResult.Errors) > 0 {
			for _, err := range nodeResult.Errors {
				o.Logger.Error(fmt.Sprintf("Node creation error: %s", err.Error()))
			}
		}
	}

	// Create relationships
	if len(o.relationships) > 0 {
		graphRels := make([]*graph.Relationship, len(o.relationships))
		for i, rel := range o.relationships {
			graphRels[i] = o.tabullariumRelationshipToGraphRelationship(rel)
		}

		o.Logger.Info(fmt.Sprintf("Creating %d relationships in Neo4j", len(graphRels)))
		relResult, err := o.db.CreateRelationships(o.ctx, graphRels)
		if err != nil {
			return fmt.Errorf("failed to create relationships: %w", err)
		}
		o.Logger.Info(fmt.Sprintf("Relationships created: %d, updated: %d", relResult.RelationshipsCreated, relResult.RelationshipsUpdated))
		if len(relResult.Errors) > 0 {
			for _, err := range relResult.Errors {
				o.Logger.Error(fmt.Sprintf("Relationship creation error: %s", err.Error()))
			}
		}
	}

	// Run AWS enrichment queries (keeping existing functionality)
	if len(o.relationships) > 0 {
		o.Logger.Info("Running AWS enrichment queries")
		eResults, err := queries.EnrichAWS(o.db)
		if err != nil {
			o.Logger.Error(fmt.Sprintf("Failed to enrich AWS data: %s", err.Error()))
		} else {
			o.Logger.Debug(fmt.Sprintf("AWS enrichment completed with %d results", len(eResults)))
		}
	}

	// Run account enrichment (this will be moved from AwsApolloControlFlow)
	err := o.enrichAccountDetails()
	if err != nil {
		o.Logger.Error(fmt.Sprintf("Failed to enrich account details: %s", err.Error()))
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
			o.Logger.Error(fmt.Sprintf("Failed to update Account node for %s: %s", accountIDStr, err.Error()))
		} else {
			accountCount++
		}
	}

	if accountCount > 0 {
		o.Logger.Info(fmt.Sprintf("Enriched %d account nodes", accountCount))
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

// tabullariumNodeToGraphNode converts a Tabularium GraphModel to Konstellation graph.Node
func (o *Neo4jGraphOutputter) tabullariumNodeToGraphNode(node model.GraphModel) *graph.Node {
	// Extract properties from the model
	properties := make(map[string]interface{})

	// Add basic properties
	properties["key"] = node.GetKey()

	// For AWSResource, add specific properties
	if awsResource, ok := node.(*model.AWSResource); ok {
		properties["arn"] = awsResource.Name
		properties["name"] = awsResource.DisplayName
		properties["accountId"] = awsResource.AccountRef
		properties["region"] = awsResource.Region
		properties["resourceType"] = string(awsResource.ResourceType)

		// Add any custom properties
		if awsResource.Properties != nil {
			for k, v := range awsResource.Properties {
				properties[k] = v
			}
		}
	}

	// Determine unique key - use "arn" for AWS resources, "key" as fallback
	uniqueKey := []string{"key"}
	if _, hasArn := properties["arn"]; hasArn {
		uniqueKey = []string{"arn"}
	}

	return &graph.Node{
		Labels:     node.GetLabels(),
		Properties: properties,
		UniqueKey:  uniqueKey,
	}
}

// tabullariumRelationshipToGraphRelationship converts a Tabularium GraphRelationship to Konstellation graph.Relationship
func (o *Neo4jGraphOutputter) tabullariumRelationshipToGraphRelationship(rel model.GraphRelationship) *graph.Relationship {
	source, target := rel.Nodes()

	// Extract properties from the relationship
	properties := make(map[string]interface{})

	// Add base relationship properties
	if base := rel.Base(); base != nil {
		properties["created"] = base.Created
		properties["visited"] = base.Visited
		properties["capability"] = base.Capability
		properties["key"] = base.Key
		if base.AttachmentPath != "" {
			properties["attachmentPath"] = base.AttachmentPath
		}
	}

	// Add specific properties based on relationship type
	switch rel.(type) {
	default:
		// Default case for unknown relationship types
	}

	return &graph.Relationship{
		StartNode:  o.tabullariumNodeToGraphNode(source),
		EndNode:    o.tabullariumNodeToGraphNode(target),
		Type:       rel.Label(),
		Properties: properties,
	}
}
