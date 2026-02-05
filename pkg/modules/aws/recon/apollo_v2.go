package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	iam "github.com/praetorian-inc/aurelian/pkg/iam/aws"
	awstransformers "github.com/praetorian-inc/aurelian/pkg/links/aws"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ApolloV2 analyzes AWS IAM permissions using plain Go patterns.
// Replaces the Janus chain-based Apollo module.
// Deprecated: V1 Apollo at pkg/links/aws/apollo_control_flow.go should use ApolloV2 instead.
type ApolloV2 struct {
	// Configuration
	Profile       string
	Regions       []string
	ResourceTypes []string
	OrgPolicyFile string // Path to organization policies JSON

	// Internal state
	cloudControlClients map[string]*cloudcontrol.Client
	config              aws.Config
}

// ApolloResult contains all IAM analysis results.
type ApolloResult struct {
	// IAM permissions (principal -> resource -> action)
	Permissions []interface{} // *output.IAMPermission or *output.SSMPermission

	// Resource-to-role relationships (EC2/Lambda -> IAM Role)
	ResourceRoleRelationships []*output.IAMPermission

	// GitHub Actions OIDC federation relationships
	GitHubActionsPermissions []*output.GitHubActionsPermission
}

// Type aliases for cleaner test assertions
type (
	IAMPermission             = output.IAMPermission
	GitHubActionsPermission   = output.GitHubActionsPermission
)

// NewApolloV2 creates a new v2 Apollo analyzer with sensible defaults.
func NewApolloV2(profile string, regions []string) *ApolloV2 {
	return &ApolloV2{
		Profile:       profile,
		Regions:       regions,
		ResourceTypes: DefaultApolloResourceTypes(),
	}
}

// DefaultApolloResourceTypes returns the resource types Apollo analyzes.
func DefaultApolloResourceTypes() []string {
	return []string{
		"AWS::IAM::Role",
		"AWS::IAM::User",
		"AWS::IAM::Group",
		"AWS::Lambda::Function",
		"AWS::EC2::Instance",
		"AWS::CloudFormation::Stack",
	}
}

// WithOrgPolicyFile sets the organization policies file path.
func (a *ApolloV2) WithOrgPolicyFile(path string) *ApolloV2 {
	a.OrgPolicyFile = path
	return a
}

// WithResourceTypes overrides the default resource types.
func (a *ApolloV2) WithResourceTypes(types []string) *ApolloV2 {
	a.ResourceTypes = types
	return a
}

// Run executes the Apollo IAM analysis workflow.
// Returns analyzed permissions as structured data.
func (a *ApolloV2) Run(ctx context.Context) (*ApolloResult, error) {
	// 1. Initialize AWS clients
	if err := a.initialize(ctx); err != nil {
		return nil, fmt.Errorf("initialization failed: %w", err)
	}

	// 2. Gather resources (using gatherResources from apollo_v2_resources.go)
	resources, err := a.gatherResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("resource gathering failed: %w", err)
	}

	// 3. Gather GAAD (using gatherGaad from apollo_v2_gaad.go)
	gaad, err := a.gatherGaad(ctx)
	if err != nil {
		return nil, fmt.Errorf("GAAD fetching failed: %w", err)
	}

	// 4. Gather resource policies (using gatherResourcePolicies from apollo_v2_policies.go)
	policies, err := a.gatherResourcePolicies(ctx, resources)
	if err != nil {
		return nil, fmt.Errorf("policy fetching failed: %w", err)
	}

	// 5. Load org policies
	orgPolicies, err := a.loadOrgPolicies()
	if err != nil {
		return nil, fmt.Errorf("org policies loading failed: %w", err)
	}

	// 6. Create PolicyData
	pd := &iam.PolicyData{
		Gaad:             gaad,
		OrgPolicies:      orgPolicies,
		ResourcePolicies: policies,
		Resources:        &resources,
	}

	// 7. Analyze permissions (REUSE GaadAnalyzer)
	analyzer := iam.NewGaadAnalyzer(pd)
	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		return nil, fmt.Errorf("permission analysis failed: %w", err)
	}

	// 8. Transform results (REUSE transformers)
	result := &ApolloResult{}
	for _, r := range summary.FullResults() {
		perm, err := awstransformers.TransformResultToPermission(r)
		if err != nil {
			continue
		}
		result.Permissions = append(result.Permissions, perm)
	}

	// 9. Add resource-role relationships
	result.ResourceRoleRelationships = a.buildResourceRoleRelationships(resources)

	// 10. Add GitHub Actions permissions (REUSE transformer)
	ghPerms, _ := awstransformers.ExtractGitHubActionsPermissions(gaad)
	result.GitHubActionsPermissions = ghPerms

	return result, nil
}

// initialize sets up AWS clients for all regions.
func (a *ApolloV2) initialize(ctx context.Context) error {
	// Load AWS config for the profile
	cfg, err := helpers.GetAWSCfg("us-east-1", a.Profile, nil, "", nil)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	a.config = cfg

	// Create CloudControl clients for each region
	a.cloudControlClients = make(map[string]*cloudcontrol.Client)
	for _, region := range a.Regions {
		regionCfg, err := helpers.GetAWSCfg(region, a.Profile, nil, "", nil)
		if err != nil {
			return fmt.Errorf("failed to load config for region %s: %w", region, err)
		}
		a.cloudControlClients[region] = cloudcontrol.NewFromConfig(regionCfg)
	}

	return nil
}

// loadOrgPolicies loads organization policies from file or uses defaults.
// Ported from apollo_control_flow.go:69-107.
func (a *ApolloV2) loadOrgPolicies() (*orgpolicies.OrgPolicies, error) {
	if a.OrgPolicyFile == "" {
		slog.Warn("No organization policies file provided, assuming p-FullAWSAccess.")
		return orgpolicies.NewDefaultOrgPolicies(), nil
	}

	fileBytes, err := os.ReadFile(a.OrgPolicyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read org policies file: %w", err)
	}

	// Try to unmarshal as array first (current format)
	var orgPoliciesArray []*orgpolicies.OrgPolicies
	if err := json.Unmarshal(fileBytes, &orgPoliciesArray); err == nil {
		if len(orgPoliciesArray) > 0 {
			return orgPoliciesArray[0], nil
		} else {
			slog.Warn("Empty organization policies array, assuming p-FullAWSAccess.")
			return orgpolicies.NewDefaultOrgPolicies(), nil
		}
	}

	// Fallback to single object format
	var orgPolicies *orgpolicies.OrgPolicies
	if err := json.Unmarshal(fileBytes, &orgPolicies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal org policies: %w", err)
	}

	return orgPolicies, nil
}

// buildResourceRoleRelationships creates assume role permissions between resources and their IAM roles.
// Ported from apollo_control_flow.go:254-324.
func (a *ApolloV2) buildResourceRoleRelationships(resources []types.EnrichedResourceDescription) []*output.IAMPermission {
	var relationships []*output.IAMPermission

	for _, resource := range resources {
		roleArn := resource.GetRoleArn()
		if roleArn == "" {
			continue
		}

		var roleName string
		accountId := resource.AccountId

		// Check if we have a full ARN or just a role name
		if strings.HasPrefix(roleArn, "arn:") {
			// Parse the ARN for proper role name
			parsedArn, err := awsarn.Parse(roleArn)
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
		sourceRef, err := awstransformers.TransformERDToResourceRef(&resource)
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

		relationships = append(relationships, assumeRolePermission)
	}

	return relationships
}
