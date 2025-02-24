package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

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

// func GraphRelationship(principal, resource, action string) {
// 	rel := graph.Relationship{}
// 	rel.Type = action
// 	rel.StartNode = graph.NodeFromEnrichedResourceDescription(principal)
// 	rel.EndNode = graph.NodeFromEnrichedResourceDescription(resource)
// 	re.Properties = evaluationResult

// }
