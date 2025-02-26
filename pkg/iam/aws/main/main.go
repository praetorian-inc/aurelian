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
	transformer "github.com/praetorian-inc/konstellation/pkg/graph/transformers/aws"
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
	/*
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

		evaluator := aws.NewPolicyEvaluator(policyData)
		analyzer := aws.NewGaadAnalyzer(policyData, evaluator)

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
	*/

	var full []aws.FullResult
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
		rel := resultToRelationship(result)
		rels = append(rels, rel)
	}

	config := &graph.Config{
		URI:      "bolt://localhost:7687",
		Username: "neo4j",
		Password: "konstellation",
	}

	ctx := context.Background()
	driver, err := adapters.NewNeo4jDatabase(config)
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
	policies := &aws.PolicyData{
		ResourcePolicies: make(map[string]*types.Policy),
	}

	// Load GAAD
	gaadData, err := loadJSONFile[types.Gaad](config.GaadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load GAAD: %w", err)
	}
	policies.Gaad = gaadData
	fmt.Println("Gaad loaded")
	fmt.Printf("%d users, %d roles, %d groups\n", len(gaadData.UserDetailList), len(gaadData.RoleDetailList), len(gaadData.GroupDetailList))

	// Load SCP if provided
	if config.SCPFile != "" {
		scpData, err := loadJSONFile[types.PolicyStatementList](config.SCPFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load SCP: %w", err)
		}
		policies.SCP = scpData
	}

	// Load RCP if provided
	if config.RCPFile != "" {
		rcpData, err := loadJSONFile[types.PolicyStatementList](config.RCPFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load RCP: %w", err)
		}
		policies.RCP = rcpData
	}

	// Load resource policies
	// TODO - Implement loading of resource policies

	if config.Resources != "" {
		resources, err := loadJSONFile[[]types.EnrichedResourceDescription](config.Resources)
		if err != nil {
			return nil, fmt.Errorf("failed to load resources: %w", err)
		}

		//policies.Resources = ResourceFilter(resources)
		policies.Resources = resources
		for _, resource := range *resources {
			if strings.Contains(resource.TypeName, "AWS::IAM::") {
				slog.Debug("Resource type: "+resource.TypeName, slog.String("arn", resource.Arn.String()))
			}
		}
		slog.Warn("Loaded resources", slog.Int("count", len(*resources)))
	}
	return policies, nil
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

func resultToRelationship(result aws.FullResult) *graph.Relationship {
	var err error
	rel := graph.Relationship{}
	rel.Type = result.Action
	//rel.StartNode = graph.

	switch result.Principal.(type) {
	case *types.UserDL:
		rel.StartNode = transformer.NodeFromUserDL(result.Principal.(*types.UserDL))
	case *types.RoleDL:
		rel.StartNode = transformer.NodeFromRoleDL(result.Principal.(*types.RoleDL))
	case *types.GroupDL:
		rel.StartNode = transformer.NodeFromGroupDL(result.Principal.(*types.GroupDL))
	case string:
		// service
		if result.Principal != nil && strings.Contains(result.Principal.(string), "amazonaws.com") {
			start := &graph.Node{
				Labels: []string{"Service", "Principal"},
				Properties: map[string]interface{}{
					"name": result.Principal,
				},
				UniqueKey: []string{"name"},
			}
			rel.StartNode = start

		}
	default:
		logger.Error(fmt.Sprintf("Unknown principal type: %v, %T", result.Principal, result.Principal))
	}

	slog.Debug(fmt.Sprintf("result: %v", result))
	slog.Debug(fmt.Sprintf("Resource ARN: %v", result.Resource))
	rel.EndNode, err = transformer.NodeFromEnrichedResourceDescription(result.Resource)
	if err != nil {
		logger.Error("Failed to create node from resource: " + err.Error())
	}

	flattenedResult, _ := utils.ConvertAndFlatten(result.Result)
	rel.Properties = make(map[string]interface{})
	for k, v := range flattenedResult {
		rel.Properties[k] = v
	}

	return &rel
}
