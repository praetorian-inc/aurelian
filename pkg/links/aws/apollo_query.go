package aws

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

type ApolloQuery struct {
	*chain.Base
	db graph.GraphDatabase
}

// QueryResultPair stores a query with its results for chaining analysis
type QueryResultPair struct {
	Query  queries.Query
	Record map[string]any
}

func NewApolloQuery(configs ...cfg.Config) chain.Link {
	a := &ApolloQuery{}
	a.Base = chain.NewBase(a, configs...)
	return a
}

func (a *ApolloQuery) Params() []cfg.Param {
	params := a.Base.Params()
	params = append(params, options.Query())
	params = append(params, options.List())
	params = append(params, options.Neo4jOptions()...)
	return params
}

func (a *ApolloQuery) Initialize() error {
	graphConfig := &graph.Config{
		URI:      a.Args()[options.Neo4jURI().Name()].(string),
		Username: a.Args()[options.Neo4jUsername().Name()].(string),
		Password: a.Args()[options.Neo4jPassword().Name()].(string),
	}

	db, err := adapters.NewNeo4jDatabase(graphConfig)
	if err != nil {
		return err
	}
	a.db = db

	err = a.db.VerifyConnectivity(context.Background())
	if err != nil {
		return err
	}

	return nil
}

func (a *ApolloQuery) Process(query string) error {
	if a.Args()[options.List().Name()].(bool) {
		qs, err := queries.GetPlatformQueries("aws", "analysis")
		if err != nil {
			return err
		}
		for _, q := range qs {
			a.Send(q.ID)
		}
		return nil
	}

	qs, err := queries.GetPlatformQueries("aws", "analysis")
	if err != nil {
		return err
	}

	// Collect all query result pairs for chaining analysis
	var queryResultPairs []QueryResultPair

	for _, q := range qs {
		if q.ID == query || query == "all" {
			res, err := queries.RunPlatformQuery(a.db, q.ID, nil)
			if err != nil {
				return err
			}

			for _, r := range res.Records {
				_, ok := r["vulnerable"].(string)
				if !ok {
					a.Logger.Error("Vulnerable entity is not a string", "vulnerable", r["vulnerable"], "query", q.ID)
					continue
				}

				// Store query result pair for chaining analysis
				queryResultPairs = append(queryResultPairs, QueryResultPair{
					Query:  q,
					Record: r,
				})

				// Process individual result and send immediately (existing behavior)
				a.processQueryResult(q, r)
			}
		}
	}

	// Analyze query results for chaining opportunities
	a.findChainablePaths(queryResultPairs)

	return nil
}

// processQueryResult processes individual query results and sends risks (extracted from original Process method)
func (a *ApolloQuery) processQueryResult(q queries.Query, r map[string]any) {
	// Convert severity to status code format
	severityCode := getSeverityCode(q.QueryMetadata.Severity)
	status := "T" + severityCode // T = Triage state, followed by severity code

	// Extract target and source ARNs directly from record
	targetARN, err := a.extractARNFromRecord(r, "target")
	if err != nil {
		a.Logger.Error("Failed to extract target ARN from record", "error", err, "query", q.ID)
		return
	}

	sourceARN, err := a.extractARNFromRecord(r, "attacker")
	if err != nil {
		a.Logger.Error("Failed to extract source ARN from record", "error", err, "query", q.ID)
		return
	}

	// Create target AWSResource
	accountRef, err := extractAccountFromARN(targetARN)
	if err != nil {
		a.Logger.Error("Failed to extract account from target ARN", "error", err, "arn", targetARN)
		return
	}

	resourceType := getResourceTypeFromARN(targetARN)
	target, err := model.NewAWSResource(targetARN, accountRef, resourceType, make(map[string]any))
	if err != nil {
		a.Logger.Error("Failed to create AWSResource", "error", err, "arn", targetARN)
		return
	}

	// Format risk name and create DNS pattern
	riskName := formatQueryName(q.QueryMetadata.Name)
	targetName := a.extractPrincipalName(targetARN)
	sourceName := a.extractPrincipalName(sourceARN)
	dns := fmt.Sprintf("%s:%s:%s", targetName, riskName, sourceName)

	// Create risk using NewRiskWithDNS
	risk := model.NewRiskWithDNS(&target, riskName, dns, status)
	risk.Priority = GetPriority(q.QueryMetadata.Severity)

	// Create proof file from record string representation
	recordObj := graph.Record(r)
	proofContent := recordObj.String()
	proofFile := risk.Proof([]byte(proofContent))
	a.Send(proofFile)

	// Create source AWSResource for relationship
	sourceAccountRef, err := extractAccountFromARN(sourceARN)
	if err != nil {
		a.Logger.Error("Failed to extract account from source ARN", "error", err, "arn", sourceARN)
		return
	}

	sourceResourceType := getResourceTypeFromARN(sourceARN)
	source, err := model.NewAWSResource(sourceARN, sourceAccountRef, sourceResourceType, make(map[string]any))
	if err != nil {
		a.Logger.Error("Failed to create source AWSResource", "error", err, "arn", sourceARN)
		return
	}

	// Create IAM relationship
	permission, ok := r["permission"].(string)
	if !ok {
		a.Logger.Error("Failed to extract permission from record", "query", q.ID)
		return
	}

	iamRel := model.NewIAMRelationship(&source, &target, permission)
	a.Send(iamRel)

	a.Send(risk)
}

func (a *ApolloQuery) Close() {
	a.db.Close()
}

func GetPriority(severity string) int {
	switch severity {
	case "LOW":
		return 3
	case "MEDIUM":
		return 5
	case "HIGH":
		return 8
	case "CRITICAL":
		return 10
	default:
		return 3
	}
}

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
		return "L" // Default to Low
	}
}

// extractPrincipalName extracts a readable name from various principal formats
func (a *ApolloQuery) extractPrincipalName(principal any) string {
	var arn string

	// Handle different formats that might come from Neo4j
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

	// Extract the last part of the ARN after the last /
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}

	// Fallback to extracting after the last :
	parts = strings.Split(arn, ":")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}

	return arn
}

// extractAccountFromARN extracts the account ID from an AWS ARN
func extractAccountFromARN(arnStr string) (string, error) {
	// ARN format: arn:aws:service:region:account:resource
	parts := strings.Split(arnStr, ":")
	if len(parts) < 5 {
		return "", fmt.Errorf("invalid ARN format: %s", arnStr)
	}
	return parts[4], nil
}

// getResourceTypeFromARN determines the CloudResourceType based on ARN pattern
func getResourceTypeFromARN(arnStr string) model.CloudResourceType {
	if strings.Contains(arnStr, ":role/") {
		return model.AWSRole
	} else if strings.Contains(arnStr, ":user/") {
		return model.AWSUser
	}
	// Default to role if we can't determine
	return model.AWSRole
}

// formatQueryName converts query metadata name to risk name format (lowercase, spaces to hyphens)
func formatQueryName(queryName string) string {
	formatted := strings.ToLower(queryName)
	formatted = strings.ReplaceAll(formatted, " ", "-")
	return formatted
}

// extractARNFromRecord extracts ARN from record field (e.g., "target", "attacker")
func (a *ApolloQuery) extractARNFromRecord(record map[string]any, field string) (string, error) {
	if arn, ok := record[field].(string); ok {
		return arn, nil
	}
	return "", fmt.Errorf("field %s not found or not a string in record", field)
}

// findChainablePaths analyzes query result pairs to find chainable attack paths
func (a *ApolloQuery) findChainablePaths(pairs []QueryResultPair) {
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			pairA := pairs[i]
			pairB := pairs[j]

			// Try chaining A -> B: target of A matches attacker of B
			if a.canChain(pairA, pairB) {
				a.createAndSendChainedRisk(pairA, pairB)
			}

			// Try chaining B -> A: target of B matches attacker of A
			if a.canChain(pairB, pairA) {
				a.createAndSendChainedRisk(pairB, pairA)
			}
		}
	}
}

// canChain checks if two query result pairs can be chained (target of first matches attacker of second)
func (a *ApolloQuery) canChain(first, second QueryResultPair) bool {
	// Extract target from first record
	firstTarget, err := a.extractARNFromRecord(first.Record, "target")
	if err != nil {
		return false
	}

	// Extract attacker from second record
	secondAttacker, err := a.extractARNFromRecord(second.Record, "attacker")
	if err != nil {
		return false
	}

	// Check if they match (using ARN as uniqueness constraint)
	return firstTarget == secondAttacker
}

// createAndSendChainedRisk creates and sends a chained risk from two query result pairs
func (a *ApolloQuery) createAndSendChainedRisk(first, second QueryResultPair) {
	// Extract ARNs for chained path
	firstAttacker, err := a.extractARNFromRecord(first.Record, "attacker")
	if err != nil {
		a.Logger.Error("Failed to extract source from first record", "error", err)
		return
	}

	connectingNode, err := a.extractARNFromRecord(first.Record, "target") // This should match attacker of second
	if err != nil {
		a.Logger.Error("Failed to extract target from first record", "error", err)
		return
	}

	secondTarget, err := a.extractARNFromRecord(second.Record, "target")
	if err != nil {
		a.Logger.Error("Failed to extract target from second record", "error", err)
		return
	}

	// Create target AWSResource using final target
	accountRef, err := extractAccountFromARN(secondTarget)
	if err != nil {
		a.Logger.Error("Failed to extract account from chained target ARN", "error", err, "arn", secondTarget)
		return
	}

	resourceType := getResourceTypeFromARN(secondTarget)
	target, err := model.NewAWSResource(secondTarget, accountRef, resourceType, make(map[string]any))
	if err != nil {
		a.Logger.Error("Failed to create AWSResource for chained risk", "error", err, "arn", secondTarget)
		return
	}

	// Use higher severity between the two queries
	severity1 := first.Query.QueryMetadata.Severity
	severity2 := second.Query.QueryMetadata.Severity
	finalSeverity := severity1
	if getSeverityPriority(severity2) > getSeverityPriority(severity1) {
		finalSeverity = severity2
	}

	// Create chained risk
	severityCode := getSeverityCode(finalSeverity)
	status := "T" + severityCode
	riskName := fmt.Sprintf("chained-%s-%s", formatQueryName(first.Query.QueryMetadata.Name), formatQueryName(second.Query.QueryMetadata.Name))

	targetName := a.extractPrincipalName(secondTarget)
	sourceName := a.extractPrincipalName(firstAttacker)
	dns := fmt.Sprintf("%s:%s:%s", targetName, riskName, sourceName)

	risk := model.NewRiskWithDNS(&target, riskName, dns, status)
	risk.Priority = GetPriority(finalSeverity)

	// Create proof content for chained attack
	chainedProofContent := fmt.Sprintf("CHAINED: (%s)-[%s]->(%s)-[%s]->(%s)",
		a.extractPrincipalName(firstAttacker),
		first.Query.QueryMetadata.Name,
		a.extractPrincipalName(connectingNode),
		second.Query.QueryMetadata.Name,
		a.extractPrincipalName(secondTarget))

	proofFile := risk.Proof([]byte(chainedProofContent))
	a.Send(proofFile)

	a.Send(risk)
}

// getSeverityPriority returns numeric priority for severity comparison
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
