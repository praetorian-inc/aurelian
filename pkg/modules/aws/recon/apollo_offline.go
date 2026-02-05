package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	iam "github.com/praetorian-inc/aurelian/pkg/iam/aws"
	awslinks "github.com/praetorian-inc/aurelian/pkg/links/aws"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/konstellation/pkg/graph"
	"github.com/praetorian-inc/konstellation/pkg/graph/adapters"
)

func init() {
	plugin.Register(&ApolloOfflineModule{})
}

// ApolloOfflineModule analyzes AWS access control details from pre-collected JSON files
type ApolloOfflineModule struct{}

func (m *ApolloOfflineModule) ID() string {
	return "apollo-offline"
}

func (m *ApolloOfflineModule) Name() string {
	return "AWS Apollo Offline"
}

func (m *ApolloOfflineModule) Description() string {
	return "Analyze AWS access control details from pre-collected JSON files using graph analysis"
}

func (m *ApolloOfflineModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *ApolloOfflineModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *ApolloOfflineModule) OpsecLevel() string {
	return "none" // No API calls
}

func (m *ApolloOfflineModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *ApolloOfflineModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html",
		"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPolicies.html",
	}
}

func (m *ApolloOfflineModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "gaad-file",
			Description: "Path to JSON file containing GetAccountAuthorizationDetails output",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "org-policies",
			Description: "Path to JSON file containing organization policies (optional)",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "resource-policies-file",
			Description: "Path to JSON file containing resource policies (optional)",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "neo4j-uri",
			Description: "Neo4j database URI",
			Type:        "string",
			Default:     "bolt://localhost:7687",
		},
		{
			Name:        "neo4j-username",
			Description: "Neo4j username",
			Type:        "string",
			Default:     "neo4j",
		},
		{
			Name:        "neo4j-password",
			Description: "Neo4j password",
			Type:        "string",
			Default:     "password",
		},
	}
}

func (m *ApolloOfflineModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get required parameters
	gaadFile, ok := cfg.Args["gaad-file"].(string)
	if !ok || gaadFile == "" {
		return nil, fmt.Errorf("gaad-file parameter is required")
	}

	// Get optional parameters with defaults
	orgPoliciesFile, _ := cfg.Args["org-policies"].(string)
	resourcePoliciesFile, _ := cfg.Args["resource-policies-file"].(string)

	neo4jURI, _ := cfg.Args["neo4j-uri"].(string)
	if neo4jURI == "" {
		neo4jURI = "bolt://localhost:7687"
	}

	neo4jUsername, _ := cfg.Args["neo4j-username"].(string)
	if neo4jUsername == "" {
		neo4jUsername = "neo4j"
	}

	neo4jPassword, _ := cfg.Args["neo4j-password"].(string)
	if neo4jPassword == "" {
		neo4jPassword = "password"
	}

	// Initialize PolicyData with empty resources slice
	resources := make([]types.EnrichedResourceDescription, 0)
	pd := &iam.PolicyData{
		Resources: &resources,
	}

	// Load data from files
	if err := m.loadDataFromFiles(pd, gaadFile, orgPoliciesFile, resourcePoliciesFile); err != nil {
		return nil, fmt.Errorf("failed to load data from files: %w", err)
	}

	// Validate that we have the required data
	if pd.Gaad == nil {
		return nil, fmt.Errorf("GAAD data is required but not loaded")
	}

	// Initialize Neo4j connection
	graphConfig := &graph.Config{
		URI:      neo4jURI,
		Username: neo4jUsername,
		Password: neo4jPassword,
	}

	db, err := adapters.NewNeo4jDatabase(graphConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Neo4j database connection: %w", err)
	}
	defer db.Close()

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	if err := db.VerifyConnectivity(ctx); err != nil {
		return nil, fmt.Errorf("failed to verify Neo4j connectivity: %w", err)
	}

	// Perform IAM analysis
	analyzer := iam.NewGaadAnalyzer(pd)
	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		return nil, fmt.Errorf("IAM analysis failed: %w", err)
	}

	// Create graph relationships
	if err := m.createGraphRelationships(ctx, summary, pd, db, cfg); err != nil {
		return nil, fmt.Errorf("failed to create graph relationships: %w", err)
	}

	// Build result
	result := plugin.Result{
		Data: map[string]any{
			"status":       "success",
			"summary":      summary,
			"gaad_file":    gaadFile,
			"org_policies": orgPoliciesFile != "",
			"resource_policies": resourcePoliciesFile != "",
		},
		Metadata: map[string]any{
			"module":      "apollo-offline",
			"platform":    "aws",
			"opsec_level": "none",
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	if cfg.Verbose {
		slog.Info("Apollo offline analysis completed successfully")
	}

	return []plugin.Result{result}, nil
}

func (m *ApolloOfflineModule) loadDataFromFiles(pd *iam.PolicyData, gaadFile, orgPoliciesFile, resourcePoliciesFile string) error {
	// Load organization policies
	if err := m.loadOrgPoliciesFromFile(pd, orgPoliciesFile); err != nil {
		return err
	}

	// Load GAAD data
	if err := m.loadGaadFromFile(pd, gaadFile); err != nil {
		return err
	}

	// Load resource policies
	if err := m.loadResourcePoliciesFromFile(pd, resourcePoliciesFile); err != nil {
		return err
	}

	return nil
}

func (m *ApolloOfflineModule) loadOrgPoliciesFromFile(pd *iam.PolicyData, orgPoliciesFile string) error {
	if orgPoliciesFile == "" {
		slog.Warn("No organization policies file provided, using default policies")
		pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		return nil
	}

	fileBytes, err := os.ReadFile(orgPoliciesFile)
	if err != nil {
		return fmt.Errorf("failed to read org policies file '%s': %w", orgPoliciesFile, err)
	}

	// Try to unmarshal as array first (matching online module output)
	var orgPoliciesArray []*orgpolicies.OrgPolicies
	if err := json.Unmarshal(fileBytes, &orgPoliciesArray); err == nil {
		if len(orgPoliciesArray) > 0 {
			pd.OrgPolicies = orgPoliciesArray[0]
		} else {
			slog.Warn("Empty organization policies array, using default policies")
			pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		}
	} else {
		// Fallback to single object format
		var orgPolicies *orgpolicies.OrgPolicies
		if err := json.Unmarshal(fileBytes, &orgPolicies); err != nil {
			return fmt.Errorf("failed to unmarshal org policies from '%s': %w", orgPoliciesFile, err)
		}
		pd.OrgPolicies = orgPolicies
	}

	slog.Info("Successfully loaded organization policies", "file", orgPoliciesFile)
	return nil
}

func (m *ApolloOfflineModule) loadGaadFromFile(pd *iam.PolicyData, gaadFile string) error {
	if gaadFile == "" {
		return fmt.Errorf("gaad-file parameter cannot be empty")
	}

	fileBytes, err := os.ReadFile(gaadFile)
	if err != nil {
		return fmt.Errorf("failed to read GAAD file '%s': %w", gaadFile, err)
	}

	// Try to unmarshal as array first (matching account-auth-details module output)
	var gaadArray []types.Gaad
	if err := json.Unmarshal(fileBytes, &gaadArray); err == nil {
		if len(gaadArray) > 0 {
			pd.Gaad = &gaadArray[0]
		} else {
			return fmt.Errorf("GAAD file '%s' contains empty array", gaadFile)
		}
	} else {
		// Fallback to single object format
		var gaad types.Gaad
		if err := json.Unmarshal(fileBytes, &gaad); err != nil {
			return fmt.Errorf("failed to unmarshal GAAD data from '%s': %w", gaadFile, err)
		}
		pd.Gaad = &gaad
	}

	slog.Info("Successfully loaded GAAD data", "file", gaadFile)
	return nil
}

func (m *ApolloOfflineModule) loadResourcePoliciesFromFile(pd *iam.PolicyData, resourcePoliciesFile string) error {
	if resourcePoliciesFile == "" {
		slog.Warn("No resource policies file provided, proceeding without resource policies")
		pd.ResourcePolicies = make(map[string]*types.Policy)
		return nil
	}

	fileBytes, err := os.ReadFile(resourcePoliciesFile)
	if err != nil {
		return fmt.Errorf("failed to read resource policies file '%s': %w", resourcePoliciesFile, err)
	}

	// Try to unmarshal as array first
	var resourcePoliciesArray []map[string]*types.Policy
	if err := json.Unmarshal(fileBytes, &resourcePoliciesArray); err == nil {
		if len(resourcePoliciesArray) > 0 {
			pd.ResourcePolicies = resourcePoliciesArray[0]
		} else {
			slog.Warn("Empty resource policies array, proceeding without resource policies")
			pd.ResourcePolicies = make(map[string]*types.Policy)
		}
	} else {
		// Parse as map[string]*types.Policy directly
		if err := json.Unmarshal(fileBytes, &pd.ResourcePolicies); err != nil {
			return fmt.Errorf("failed to unmarshal resource policies from '%s': %w", resourcePoliciesFile, err)
		}
	}

	if pd.ResourcePolicies == nil {
		pd.ResourcePolicies = make(map[string]*types.Policy)
	}

	slog.Info("Successfully loaded resource policies", "file", resourcePoliciesFile, "count", len(pd.ResourcePolicies))
	return nil
}

func (m *ApolloOfflineModule) createGraphRelationships(ctx context.Context, summary *iam.PermissionsSummary, pd *iam.PolicyData, db graph.GraphDatabase, cfg plugin.Config) error {
	// Transform and send IAM permission relationships to Neo4j
	fullResults := summary.FullResults()

	if cfg.Verbose {
		slog.Info("Processing IAM relationships", "count", len(fullResults))
	}

	for i, result := range fullResults {
		rel, err := awslinks.TransformResultToPermission(result)
		if err != nil {
			slog.Error("Failed to transform relationship", "index", i, "error", err)
			continue
		}

		// Send to Neo4j using direct query
		if err := m.sendPermissionToNeo4j(ctx, db, rel); err != nil {
			slog.Error("Failed to send relationship to Neo4j", "error", err)
		}
	}

	// Create assume role relationships between resources and their IAM roles
	if err := m.sendResourceRoleRelationships(ctx, db, pd); err != nil {
		slog.Error("Failed to create assume role relationships", "error", err)
	}

	// Process GitHub Actions relationships
	githubRelationships, err := awslinks.ExtractGitHubActionsPermissions(pd.Gaad)
	if err != nil {
		slog.Error("Failed to extract GitHub Actions relationships", "error", err)
	} else if len(githubRelationships) > 0 {
		if cfg.Verbose {
			slog.Info("Processing GitHub Actions relationships", "count", len(githubRelationships))
		}
		for _, rel := range githubRelationships {
			if err := m.sendPermissionToNeo4j(ctx, db, rel); err != nil {
				slog.Error("Failed to send GitHub relationship to Neo4j", "error", err)
			}
		}
	}

	return nil
}

func (m *ApolloOfflineModule) sendPermissionToNeo4j(ctx context.Context, db graph.GraphDatabase, permission any) error {
	// This would need to use the Neo4j driver to create the relationship
	// For now, this is a placeholder that would need the actual implementation
	// from the Neo4jGraphOutputter
	_ = ctx
	_ = db
	_ = permission
	// TODO: Implement direct Neo4j relationship creation
	return nil
}

func (m *ApolloOfflineModule) sendResourceRoleRelationships(ctx context.Context, db graph.GraphDatabase, pd *iam.PolicyData) error {
	if pd.Resources == nil || len(*pd.Resources) == 0 {
		return nil
	}

	for _, resource := range *pd.Resources {
		roleArn := resource.GetRoleArn()
		if roleArn == "" {
			continue
		}

		var roleName string
		var accountId string = resource.AccountId

		// Check if we have a full ARN or just a role name
		if strings.HasPrefix(roleArn, "arn:") {
			// Parse the ARN for proper role name
			parsedArn, err := arn.Parse(roleArn)
			if err != nil {
				slog.Error("Failed to parse role ARN", "arn", roleArn, "error", err)
				continue
			}

			// If we have a valid ARN, use the account ID from it
			accountId = parsedArn.AccountID

			// Extract role name from resource field
			roleName = parsedArn.Resource
			// Handle the case where the resource includes a path like "role/rolename"
			if strings.Contains(roleName, "/") {
				parts := strings.Split(roleName, "/")
				roleName = parts[len(parts)-1]
			}
		} else {
			// If no ARN format, assume it's a direct role name
			roleName = roleArn
			// Use the resource's account ID for constructing the role ARN
			roleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, roleName)
		}

		// Create ResourceRef for the source (resource with the role)
		sourceRef, err := awslinks.TransformERDToResourceRef(&resource)
		if err != nil {
			slog.Error("Failed to transform resource", "arn", resource.Arn.String(), "error", err)
			continue
		}

		// Create ResourceRef for the target (IAM role)
		targetRef := output.ResourceRef{
			Platform: "aws",
			Type:     "iam-role",
			ID:       roleArn,
			Account:  accountId,
		}

		// Create the assume role permission
		assumeRolePermission := &output.IAMPermission{
			Source:     sourceRef,
			Target:     targetRef,
			Permission: "sts:AssumeRole",
			Effect:     "Allow",
			Capability: "apollo-resource-role-mapping",
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
		}

		// Send to Neo4j
		if err := m.sendPermissionToNeo4j(ctx, db, assumeRolePermission); err != nil {
			slog.Error("Failed to send assume role permission", "error", err)
		}
	}

	return nil
}
