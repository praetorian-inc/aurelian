package aws

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
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AwsApolloControlFlow struct {
	*base.NativeAWSLink
	pd *iam.PolicyData
}

func (a *AwsApolloControlFlow) SupportedResourceTypes() []string {
	return []string{
		"AWS::IAM::Role",
		"AWS::IAM::User",
		"AWS::IAM::Group",
		"AWS::Lambda::Function",
		"AWS::EC2::Instance",
		"AWS::CloudFormation::Stack",
	}
}

func NewAwsApolloControlFlow(args map[string]any) *AwsApolloControlFlow {
	return &AwsApolloControlFlow{
		NativeAWSLink: base.NewNativeAWSLink("apollo-control-flow", args),
	}
}

func (a *AwsApolloControlFlow) loadOrgPolicies() error {
	orgPolFile := a.ArgString("org-policies", "")
	if orgPolFile == "" {
		slog.Warn("No organization policies file provided, assuming p-FullAWSAccess.")
		a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		return nil
	}

	fileBytes, err := os.ReadFile(orgPolFile)
	if err != nil {
		return fmt.Errorf("failed to read org policies file: %w", err)
	}

	// Try to unmarshal as array first (current format)
	var orgPoliciesArray []*orgpolicies.OrgPolicies
	if err := json.Unmarshal(fileBytes, &orgPoliciesArray); err == nil {
		if len(orgPoliciesArray) > 0 {
			a.pd.OrgPolicies = orgPoliciesArray[0]
		} else {
			slog.Warn("Empty organization policies array, assuming p-FullAWSAccess.")
			a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		}
	} else {
		// Fallback to single object format
		var orgPolicies *orgpolicies.OrgPolicies
		if err := json.Unmarshal(fileBytes, &orgPolicies); err != nil {
			return fmt.Errorf("failed to unmarshal org policies: %w", err)
		}
		a.pd.OrgPolicies = orgPolicies
	}

	return nil
}

func (a *AwsApolloControlFlow) Process(ctx context.Context, input any) ([]any, error) {
	resourceType, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string, got %T", input)
	}

	// Initialize PolicyData with an empty slice of resources
	resources := make([]types.EnrichedResourceDescription, 0)
	a.pd = &iam.PolicyData{
		Resources: &resources,
	}
	if err := a.loadOrgPolicies(); err != nil {
		return nil, err
	}

	err := a.gatherResources(ctx, resourceType)
	if err != nil {
		return nil, err
	}

	err = a.gatherResourcePolicies(ctx)
	if err != nil {
		return nil, err
	}

	err = a.gatherGaadDetails(ctx)
	if err != nil {
		return nil, err
	}

	analyzer := iam.NewGaadAnalyzer(a.pd)
	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		return nil, err
	}

	// Collect all outputs
	var outputs []any

	// Transform and send IAM permission relationships
	fullResults := summary.FullResults()

	for _, result := range fullResults {
		perm, err := TransformResultToPermission(result)
		if err != nil {
			continue
		}
		outputs = append(outputs, perm)
	}

	// Create assume role relationships between resources and their IAM roles
	roleOutputs, err := a.sendResourceRoleRelationships()
	if err == nil {
		outputs = append(outputs, roleOutputs...)
	}

	// Process GitHub Actions federated identity relationships
	githubOutputs, err := a.processGitHubActionsFederation()
	if err == nil {
		outputs = append(outputs, githubOutputs...)
	}

	return outputs, nil
}

func (a *AwsApolloControlFlow) gatherResources(ctx context.Context, resourceType string) error {
	// TODO: This method needs to be reimplemented without chains
	// For now, return empty to allow compilation
	return nil
}

func (a *AwsApolloControlFlow) gatherResourcePolicies(ctx context.Context) error {
	// Initialize map if nil
	if a.pd.ResourcePolicies == nil {
		a.pd.ResourcePolicies = make(map[string]*types.Policy)
	}

	// TODO: This method needs to be reimplemented without chains
	// For now, return empty to allow compilation
	return nil
}

func (a *AwsApolloControlFlow) gatherGaadDetails(ctx context.Context) error {
	// TODO: This method needs to be reimplemented without chains
	// For now, return empty to allow compilation
	return nil
}

// sendResourceRoleRelationships creates assume role permissions using Pure CLI types
func (a *AwsApolloControlFlow) sendResourceRoleRelationships() ([]any, error) {
	var outputs []any
	if a.pd.Resources == nil || len(*a.pd.Resources) == 0 {
		return outputs, nil
	}

	for _, resource := range *a.pd.Resources {
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
				a.Logger().Error(fmt.Sprintf("Failed to parse role ARN %s: %s", roleArn, err.Error()))
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
		sourceRef, err := TransformERDToResourceRef(&resource)
		if err != nil {
			a.Logger().Error(fmt.Sprintf("Failed to transform resource %s: %s", resource.Arn.String(), err.Error()))
			continue
		}

		// Create ResourceRef for the target (IAM role)
		targetRef := output.ResourceRef{
			Platform: "aws",
			Type:     "iam-role",
			ID:       roleArn,
			Account:  accountId,
		}

		// Create the assume role permission (Pure CLI - no Neo4j key knowledge)
		assumeRolePermission := &output.IAMPermission{
			Source:     sourceRef,
			Target:     targetRef,
			Permission: "sts:AssumeRole",
			Effect:     "Allow",
			Capability: "apollo-resource-role-mapping",
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
		}

		// Add to outputs
		outputs = append(outputs, assumeRolePermission)
	}

	return outputs, nil
}

// processGitHubActionsFederation processes GitHub Actions federated identity permissions
func (a *AwsApolloControlFlow) processGitHubActionsFederation() ([]any, error) {
	var outputs []any

	if a.pd == nil || a.pd.Gaad == nil {
		return outputs, nil
	}

	// Extract all GitHub Actions Repository→Role permissions from GAAD data
	permissions, err := ExtractGitHubActionsPermissions(a.pd.Gaad)
	if err != nil {
		return nil, fmt.Errorf("failed to extract GitHub Actions permissions: %w", err)
	}

	// Collect all permissions as outputs
	for _, perm := range permissions {
		outputs = append(outputs, perm)
	}

	return outputs, nil
}
