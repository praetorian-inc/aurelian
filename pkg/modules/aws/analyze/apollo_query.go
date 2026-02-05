package analyze

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/konstellation/pkg/graph"
	"github.com/praetorian-inc/konstellation/pkg/graph/adapters"
	"github.com/praetorian-inc/konstellation/pkg/graph/queries"
)

func init() {
	plugin.Register(&ApolloQuery{})
}

// ApolloQuery runs queries against the Apollo graph database to identify AWS security risks
type ApolloQuery struct{}

// QueryResultPair stores a query with its results for chaining analysis
type QueryResultPair struct {
	Query  queries.Query
	Record map[string]any
}

func (m *ApolloQuery) ID() string {
	return "apollo-query"
}

func (m *ApolloQuery) Name() string {
	return "Apollo Query"
}

func (m *ApolloQuery) Description() string {
	return "Runs a query against the Apollo graph database to identify AWS IAM permission chains and security risks"
}

func (m *ApolloQuery) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *ApolloQuery) Category() plugin.Category {
	return plugin.CategoryAnalyze
}

func (m *ApolloQuery) OpsecLevel() string {
	return "safe"
}

func (m *ApolloQuery) Authors() []string {
	return []string{"Praetorian"}
}

func (m *ApolloQuery) References() []string {
	return []string{}
}

func (m *ApolloQuery) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "query",
			Description: "Query ID to execute (or 'all' for all queries)",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "list",
			Description: "List available queries without executing",
			Type:        "bool",
			Required:    false,
			Default:     false,
		},
		{
			Name:        "neo4j-uri",
			Description: "Neo4j database URI",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "neo4j-username",
			Description: "Neo4j username",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "neo4j-password",
			Description: "Neo4j password",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "module-name",
			Description: "Name of the module for dynamic file naming",
			Type:        "string",
			Required:    false,
			Default:     "apollo-query",
		},
	}
}

func (m *ApolloQuery) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Extract parameters
	query, _ := cfg.Args["query"].(string)
	if query == "" {
		return nil, fmt.Errorf("query parameter is required")
	}

	listMode, _ := cfg.Args["list"].(bool)
	neo4jURI, _ := cfg.Args["neo4j-uri"].(string)
	neo4jUsername, _ := cfg.Args["neo4j-username"].(string)
	neo4jPassword, _ := cfg.Args["neo4j-password"].(string)

	if neo4jURI == "" || neo4jUsername == "" || neo4jPassword == "" {
		return nil, fmt.Errorf("neo4j connection parameters are required")
	}

	// Check context cancellation
	if cfg.Context != nil {
		select {
		case <-cfg.Context.Done():
			return nil, cfg.Context.Err()
		default:
		}
	}

	// Initialize Neo4j connection
	graphConfig := &graph.Config{
		URI:      neo4jURI,
		Username: neo4jUsername,
		Password: neo4jPassword,
	}

	db, err := adapters.NewNeo4jDatabase(graphConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Neo4j: %w", err)
	}
	defer db.Close()

	// Verify connectivity
	if err := db.VerifyConnectivity(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to verify Neo4j connectivity: %w", err)
	}

	// Get available queries
	qs, err := queries.GetPlatformQueries("aws", "analysis")
	if err != nil {
		return nil, fmt.Errorf("failed to get platform queries: %w", err)
	}

	// List mode: return query IDs
	if listMode {
		var results []plugin.Result
		for _, q := range qs {
			results = append(results, plugin.Result{
				Data: map[string]any{
					"query_id":    q.ID,
					"name":        q.QueryMetadata.Name,
					"description": q.QueryMetadata.Description,
					"severity":    q.QueryMetadata.Severity,
				},
			})
		}
		return results, nil
	}

	// Execute queries and collect results
	var results []plugin.Result
	var queryResultPairs []QueryResultPair

	for _, q := range qs {
		if q.ID == query || query == "all" {
			// Check context cancellation before executing query
			if cfg.Context != nil {
				select {
				case <-cfg.Context.Done():
					return results, cfg.Context.Err()
				default:
				}
			}

			res, err := queries.RunPlatformQuery(db, q.ID, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to run query %s: %w", q.ID, err)
			}

			for _, r := range res.Records {
				// Store for chaining analysis
				queryResultPairs = append(queryResultPairs, QueryResultPair{
					Query:  q,
					Record: r,
				})

				// Process individual result
				individualResults, err := m.processQueryResult(q, r)
				if err != nil {
					if cfg.Verbose {
						fmt.Fprintf(cfg.Output, "Warning: failed to process result for query %s: %v\n", q.ID, err)
					}
					continue
				}
				results = append(results, individualResults...)
			}
		}
	}

	// Find and process chained attack paths
	chainedResults := m.findChainablePaths(queryResultPairs)
	results = append(results, chainedResults...)

	return results, nil
}

// processQueryResult processes individual query results and creates risks
func (m *ApolloQuery) processQueryResult(q queries.Query, r map[string]any) ([]plugin.Result, error) {
	// Extract target and source ARNs
	targetARN, err := extractARNFromRecord(r, "target")
	if err != nil {
		return nil, fmt.Errorf("failed to extract target ARN: %w", err)
	}

	sourceARN, err := extractARNFromRecord(r, "attacker")
	if err != nil {
		return nil, fmt.Errorf("failed to extract source ARN: %w", err)
	}

	// Create ResourceRefs
	targetRef, err := createResourceRefFromARN(targetARN)
	if err != nil {
		return nil, fmt.Errorf("failed to create target ResourceRef: %w", err)
	}

	sourceRef, err := createResourceRefFromARN(sourceARN)
	if err != nil {
		return nil, fmt.Errorf("failed to create source ResourceRef: %w", err)
	}

	// Format risk name and DNS
	severityCode := getSeverityCode(q.QueryMetadata.Severity)
	status := "T" + severityCode
	riskName := formatQueryName(q.QueryMetadata.Name)
	targetName := extractPrincipalName(targetARN)
	sourceName := extractPrincipalName(sourceARN)
	dns := fmt.Sprintf("%s:%s:%s", targetName, riskName, sourceName)

	// Create proof content
	recordObj := graph.Record(r)
	proofContent := recordObj.String()

	// Create cloud resource
	targetResource := &output.CloudResource{
		Platform:     "aws",
		ResourceType: targetRef.Type,
		ResourceID:   targetRef.ID,
		AccountRef:   targetRef.Account,
	}

	// Create risk
	risk := &output.Risk{
		Target:      targetResource,
		Name:        riskName,
		DNS:         dns,
		Status:      status,
		Source:      "apollo-query-analysis",
		Description: q.QueryMetadata.Description,
		Comment:     proofContent,
	}

	// Extract permission
	permission, ok := r["permission"].(string)
	if !ok {
		return nil, fmt.Errorf("permission field not found or not a string")
	}

	// Create IAM permission
	iamPermission := &output.IAMPermission{
		Source:     sourceRef,
		Target:     targetRef,
		Permission: permission,
		Effect:     "Allow",
		Capability: "apollo-query-analysis",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	return []plugin.Result{
		{Data: iamPermission},
		{Data: risk},
	}, nil
}

// findChainablePaths analyzes query result pairs to find chainable attack paths
func (m *ApolloQuery) findChainablePaths(pairs []QueryResultPair) []plugin.Result {
	var results []plugin.Result

	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			pairA := pairs[i]
			pairB := pairs[j]

			// Try chaining A -> B
			if canChain(pairA, pairB) {
				if chainedResult := createChainedRisk(pairA, pairB); chainedResult != nil {
					results = append(results, *chainedResult)
				}
			}

			// Try chaining B -> A
			if canChain(pairB, pairA) {
				if chainedResult := createChainedRisk(pairB, pairA); chainedResult != nil {
					results = append(results, *chainedResult)
				}
			}
		}
	}

	return results
}

// canChain checks if two query result pairs can be chained
func canChain(first, second QueryResultPair) bool {
	firstTarget, err := extractARNFromRecord(first.Record, "target")
	if err != nil {
		return false
	}

	secondAttacker, err := extractARNFromRecord(second.Record, "attacker")
	if err != nil {
		return false
	}

	return firstTarget == secondAttacker
}

// createChainedRisk creates a chained risk from two query result pairs
func createChainedRisk(first, second QueryResultPair) *plugin.Result {
	// Extract ARNs
	firstAttacker, err := extractARNFromRecord(first.Record, "attacker")
	if err != nil {
		return nil
	}

	connectingNode, err := extractARNFromRecord(first.Record, "target")
	if err != nil {
		return nil
	}

	secondTarget, err := extractARNFromRecord(second.Record, "target")
	if err != nil {
		return nil
	}

	// Create target ResourceRef
	targetRef, err := createResourceRefFromARN(secondTarget)
	if err != nil {
		return nil
	}

	// Use higher severity
	severity1 := first.Query.QueryMetadata.Severity
	severity2 := second.Query.QueryMetadata.Severity
	finalSeverity := severity1
	if getSeverityPriority(severity2) > getSeverityPriority(severity1) {
		finalSeverity = severity2
	}

	// Create chained risk
	severityCode := getSeverityCode(finalSeverity)
	status := "T" + severityCode
	riskName := fmt.Sprintf("chained-%s-%s",
		formatQueryName(first.Query.QueryMetadata.Name),
		formatQueryName(second.Query.QueryMetadata.Name))

	targetName := extractPrincipalName(secondTarget)
	sourceName := extractPrincipalName(firstAttacker)
	dns := fmt.Sprintf("%s:%s:%s", targetName, riskName, sourceName)

	chainedProofContent := fmt.Sprintf("CHAINED: (%s)-[%s]->(%s)-[%s]->(%s)",
		extractPrincipalName(firstAttacker),
		first.Query.QueryMetadata.Name,
		extractPrincipalName(connectingNode),
		second.Query.QueryMetadata.Name,
		extractPrincipalName(secondTarget))

	targetResource := &output.CloudResource{
		Platform:     "aws",
		ResourceType: targetRef.Type,
		ResourceID:   targetRef.ID,
		AccountRef:   targetRef.Account,
	}

	chainedDescription := fmt.Sprintf("Chained attack path combining %s and %s",
		first.Query.QueryMetadata.Name, second.Query.QueryMetadata.Name)

	risk := &output.Risk{
		Target:      targetResource,
		Name:        riskName,
		DNS:         dns,
		Status:      status,
		Source:      "apollo-query-analysis-chained",
		Description: chainedDescription,
		Comment:     chainedProofContent,
	}

	return &plugin.Result{Data: risk}
}

// Helper functions

func getSeverityCode(severity string) string {
	switch strings.ToUpper(severity) {
	case "LOW":
		return "L"
	case "MEDIUM":
		return "M"
	case "HIGH":
		return "H"
	case "CRITICAL":
		return "C"
	case "INFO", "INFORMATIONAL":
		return "I"
	case "EXPOSURE":
		return "E"
	default:
		return "L"
	}
}

func getSeverityPriority(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 1
	}
}

func extractPrincipalName(principal any) string {
	var arn string

	switch p := principal.(type) {
	case string:
		arn = p
	case map[string]any:
		if arnVal, ok := p["arn"]; ok {
			if arnStr, ok := arnVal.(string); ok {
				arn = arnStr
			}
		}
	default:
		return ""
	}

	if arn == "" {
		return ""
	}

	// Extract the last part after /
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}

	// Fallback to last part after :
	parts = strings.Split(arn, ":")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}

	return arn
}

func extractAccountFromARN(arnStr string) (string, error) {
	parts := strings.Split(arnStr, ":")
	if len(parts) < 5 {
		return "", fmt.Errorf("invalid ARN format: %s", arnStr)
	}
	return parts[4], nil
}

func getResourceTypeFromARN(arnStr string) string {
	if strings.Contains(arnStr, ":role/") {
		return "iam-role"
	} else if strings.Contains(arnStr, ":user/") {
		return "iam-user"
	}
	return "iam-role"
}

func createResourceRefFromARN(arnStr string) (output.ResourceRef, error) {
	accountRef, err := extractAccountFromARN(arnStr)
	if err != nil {
		return output.ResourceRef{}, fmt.Errorf("failed to extract account from ARN: %w", err)
	}

	resourceType := getResourceTypeFromARN(arnStr)

	return output.ResourceRef{
		Platform: "aws",
		Type:     resourceType,
		ID:       arnStr,
		Account:  accountRef,
	}, nil
}

func formatQueryName(queryName string) string {
	formatted := strings.ToLower(queryName)
	formatted = strings.ReplaceAll(formatted, " ", "-")
	return formatted
}

func extractARNFromRecord(record map[string]any, field string) (string, error) {
	if arn, ok := record[field].(string); ok {
		return arn, nil
	}
	return "", fmt.Errorf("field %s not found or not a string in record", field)
}
