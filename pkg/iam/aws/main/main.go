package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/praetorian-inc/konstellation/pkg/graph"
	"github.com/praetorian-inc/konstellation/pkg/graph/adapters"
	"github.com/praetorian-inc/konstellation/pkg/graph/queries"
	transformers "github.com/praetorian-inc/konstellation/pkg/graph/transformers/aws"
	"github.com/praetorian-inc/konstellation/pkg/graph/utils"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var logger = logs.NewLogger()

// Config holds the application configuration from CLI args
type Config struct {
	GaadFile         string
	SCPFile          string
	RCPFile          string
	ResourcePolicies string
	Resources        string
	Debug            bool
}

func main() {
	logs.ConfigureDefaults("debug")
	// Initialize configuration from command line flags
	config := parseFlags()
	if config.Debug {
		logs.ConfigureDefaults("debug")
	}

	// Load and parse all policy files
	policyData, err := loadPolicies(config)
	if err != nil {
		log.Fatalf("Failed to load policies: %v", err)
	}

	analyzer := aws.NewGaadAnalyzer(policyData)

	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		// Handle error
		logger.Error("Failed to analyze policy permissions: " + err.Error())
	}

	for _, result := range summary.GetResults() {
		fmt.Printf("Principal: %s\n", result.PrincipalArn)
		fmt.Printf("Account: %s\n", result.AccountID)
		for resource, actions := range result.ResourcePerms {
			fmt.Printf("  Resource: %s\n", resource)
			fmt.Printf("    Allowed Actions: %v\n", actions)
		}
	}

	full := summary.FullResults()
	for _, result := range full {
		switch result.Principal.(type) {
		case *types.UserDL:
			fmt.Printf("Principal: %s\n", result.Principal.(*types.UserDL).Arn)
		case *types.RoleDL:
			fmt.Printf("Principal: %s\n", result.Principal.(*types.RoleDL).Arn)
		case *types.GroupDL:
			fmt.Printf("Principal: %s\n", result.Principal.(*types.GroupDL).Arn)
		default:
			fmt.Printf("Principal: %v\n", result.Principal)
		}
		fmt.Printf("Resource: %s\n", result.Resource.Arn)
		fmt.Printf("Action: %v\n", result.Action)
		fmt.Printf("ER: %v\n", result.Result)
	}

	fullResultsJSON, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal full results to JSON: %v", err)
	}

	err = os.WriteFile("full_results.json", fullResultsJSON, 0644)
	if err != nil {
		log.Fatalf("Failed to write full results to file: %v", err)
	}

	//var full []aws.FullResult
	data, err := os.ReadFile("full_results.json")
	if err != nil {
		log.Fatalf("Failed to read full results file: %v", err)
	}
	err = json.Unmarshal(data, &full)
	if err != nil {
		log.Fatalf("Failed to unmarshal full results: %v", err)
	}

	rels := make([]*graph.Relationship, 0)
	for _, result := range full {
		rel, err := resultToRelationship(result)
		if err != nil {
			logger.Error("Failed to create relationship: " + err.Error())
			continue
		}
		rels = append(rels, rel)
	}

	graphConfig := &graph.Config{
		URI:      "bolt://localhost:7687",
		Username: "neo4j",
		Password: "konstellation",
	}

	ctx := context.Background()
	driver, err := adapters.NewNeo4jDatabase(graphConfig)
	if err != nil {
		logger.Error("Failed to create Neo4j driver: " + err.Error())
		os.Exit(1)
	}

	res, err := driver.CreateRelationships(ctx, rels)
	if err != nil {
		logger.Error("Failed to create relationships: " + err.Error())
	}

	res.PrintSummary()

	// Enrich data
	eResults, err := queries.EnrichAWS(driver)
	if err != nil {
		logger.Error("Failed to enrich data: " + err.Error())
	}

	fmt.Println("Enriched results: ", eResults)
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.GaadFile, "gaad", "", "Path to GAAD JSON file")
	flag.StringVar(&config.SCPFile, "scp", "", "Path to SCP JSON file")
	flag.StringVar(&config.RCPFile, "rcp", "", "Path to RCP JSON file")
	flag.StringVar(&config.ResourcePolicies, "resource-policies", "", "Path to resource policies")
	flag.StringVar(&config.Resources, "resources", "", "list-all resources output")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug logging")

	flag.Parse()

	// Validate required flags
	if config.GaadFile == "" {
		log.Fatal("GAAD file path is required")
	}

	return config
}

func loadPolicies(config *Config) (*aws.PolicyData, error) {

	// Load GAAD
	gaadData, err := loadJSONFile[types.Gaad](config.GaadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load GAAD: %w", err)
	}

	fmt.Println("Gaad loaded")
	fmt.Printf("%d users, %d roles, %d groups\n", len(gaadData.UserDetailList), len(gaadData.RoleDetailList), len(gaadData.GroupDetailList))

	// Load SCP if provided
	var scpData *types.PolicyStatementList
	if config.SCPFile != "" {
		scpData, err = loadJSONFile[types.PolicyStatementList](config.SCPFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load SCP: %w", err)
		}
	}

	// Load RCP if provided
	var rcpData *types.PolicyStatementList
	if config.RCPFile != "" {
		rcpData, err = loadJSONFile[types.PolicyStatementList](config.RCPFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load RCP: %w", err)
		}
	}

	// Load resource policies
	// TODO - Implement loading of resource policies

	var resources *[]types.EnrichedResourceDescription
	if config.Resources != "" {
		resources, err = loadJSONFile[[]types.EnrichedResourceDescription](config.Resources)
		if err != nil {
			return nil, fmt.Errorf("failed to load resources: %w", err)
		}

		// //policies.Resources = ResourceFilter(resources)
		// for _, resource := range *resources {
		// 	if strings.Contains(resource.TypeName, "AWS::IAM::") {
		// 		slog.Debug("Resource type: "+resource.TypeName, slog.String("arn", resource.Arn.String()))
		// 	}
		// }
		slog.Warn("Loaded resources", slog.Int("count", len(*resources)))
	}

	pd := aws.NewPolicyData(gaadData, scpData, rcpData, nil, resources)
	return pd, nil
}

// Generic function to load and unmarshal JSON files
func loadJSONFile[T any](filename string) (*T, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func resultToRelationship(result aws.FullResult) (*graph.Relationship, error) {
	rel := graph.Relationship{}
	rel.Type = result.Action

	// Handle Principal (StartNode)
	switch p := result.Principal.(type) {
	case *types.UserDL:
		rel.StartNode = transformers.NodeFromUserDL(p)
	case *types.RoleDL:
		rel.StartNode = transformers.NodeFromRoleDL(p)
	case *types.GroupDL:
		rel.StartNode = transformers.NodeFromGroupDL(p)
	case string:
		// Handle service principals
		if strings.Contains(p, "amazonaws.com") || strings.Contains(p, "aws:service") {
			serviceName := p

			// Extract service name from ARN format if needed
			if strings.HasPrefix(p, "arn:aws:iam::aws:service/") {
				serviceName = strings.TrimPrefix(p, "arn:aws:iam::aws:service/")
			}

			rel.StartNode = &graph.Node{
				Labels: []string{"Service", "Principal", "Resource"},
				Properties: map[string]interface{}{
					"name":     serviceName,
					"arn":      p,
					"fullName": p,
				},
				UniqueKey: []string{"name"},
			}
		} else {
			// Handle other string principal types (ARNs, etc.)
			principalName := p

			// Try to extract a short name from ARN
			if strings.HasPrefix(p, "arn:") {
				parts := strings.Split(p, "/")
				if len(parts) > 1 {
					principalName = parts[len(parts)-1]
				}
			}

			rel.StartNode = &graph.Node{
				Labels: []string{"Principal"},
				Properties: map[string]interface{}{
					"arn":  p,
					"name": principalName,
				},
				UniqueKey: []string{"arn"},
			}
		}
	default:
		return nil, fmt.Errorf("unknown principal type: %T", p)
	}

	// Ensure StartNode is not nil
	if rel.StartNode == nil {
		return nil, fmt.Errorf("could not create start node for principal: %v", result.Principal)
	}

	// Handle Resource (EndNode)
	if result.Resource == nil {
		return nil, fmt.Errorf("nil resource")
	}

	var err error
	rel.EndNode, err = transformers.NodeFromEnrichedResourceDescription(result.Resource)
	if err != nil {
		return nil, fmt.Errorf("failed to create node from resource: %w", err)
	}

	// Process Result
	if result.Result != nil {
		flattenedResult, err := utils.ConvertAndFlatten(result.Result)
		if err != nil {
			rel.Properties = map[string]interface{}{
				"allowed": result.Result.Allowed,
				"details": result.Result.EvaluationDetails,
			}
		} else {
			rel.Properties = flattenedResult
		}
	} else {
		rel.Properties = map[string]interface{}{
			"allowed": false,
			"details": "No evaluation result available",
		}
	}

	return &rel, nil
}
