package orgpolicies

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/organizations"
	awstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// OrganizationsClient defines the narrow interface needed for AWS Organizations operations.
// This interface enables testing with mocks instead of requiring real AWS credentials.
type OrganizationsClient interface {
	ListRoots(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListAccountsForParent(ctx context.Context, params *organizations.ListAccountsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error)
	ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicy(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
}

// CollectorOptions contains configuration for the org policies collector.
type CollectorOptions struct {
	Profile    string
	ProfileDir string
}

// CollectOrgPolicies is the main entry point for collecting AWS Organizations policies.
// It collects the organization hierarchy, SCPs, and RCPs, then builds the unified OrgPolicies structure.
func CollectOrgPolicies(ctx context.Context, opts CollectorOptions) (*OrgPolicies, error) {
	slog.Debug("Collecting AWS Organization Policies", "profile", opts.Profile)

	// Organizations API is global, use us-east-1
	cfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    opts.Profile,
		ProfileDir: opts.ProfileDir,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config: %w", err)
	}

	client := organizations.NewFromConfig(cfg)

	orgHierarchy, err := collectOrganizationHierarchy(ctx, client)
	if err != nil {
		slog.Error("Error collecting organization hierarchy", "error", err)
		return nil, err
	}

	scps, err := collectPolicies(ctx, client, awstypes.PolicyTypeServiceControlPolicy)
	if err != nil {
		slog.Error("Error collecting organization SCPs", "error", err)
		return nil, err
	}

	rcps, err := collectPolicies(ctx, client, awstypes.PolicyTypeResourceControlPolicy)
	if err != nil {
		slog.Error("Error collecting organization RCPs", "error", err)
		return nil, err
	}

	if rcps == nil {
		rcps = []PolicyData{}
	}

	orgPolicies := BuildOrgPoliciesFromHierarchy(orgHierarchy, scps, rcps)
	return orgPolicies, nil
}

// collectOrganizationHierarchy recursively collects the AWS Organizations hierarchy.
func collectOrganizationHierarchy(ctx context.Context, client OrganizationsClient) (*OrgUnit, error) {
	slog.Debug("Collecting Organization Hierarchy")

	roots, err := client.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list roots: %w", err)
	}
	if len(roots.Roots) == 0 {
		return nil, fmt.Errorf("no root OU found")
	}

	rootOU := OrgUnit{
		ID:   *roots.Roots[0].Id,
		Name: *roots.Roots[0].Name,
	}

	if err := processOU(ctx, client, &rootOU); err != nil {
		return nil, err
	}

	return &rootOU, nil
}

// processOU recursively processes an organizational unit, collecting its child OUs and accounts concurrently.
func processOU(ctx context.Context, client OrganizationsClient, ou *OrgUnit) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	// Collect all child OUs with pagination
	var childOUs []awstypes.OrganizationalUnit
	var nextToken *string

	for {
		input := &organizations.ListOrganizationalUnitsForParentInput{
			ParentId: &ou.ID,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		output, err := client.ListOrganizationalUnitsForParent(ctx, input)
		if err != nil {
			return fmt.Errorf("failed to list child OUs for %s: %w", ou.ID, err)
		}

		childOUs = append(childOUs, output.OrganizationalUnits...)
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	// Process child OUs concurrently
	for _, childOU := range childOUs {
		wg.Add(1)
		go func(child awstypes.OrganizationalUnit) {
			defer wg.Done()
			childUnit := OrgUnit{
				ID:   *child.Id,
				Name: *child.Name,
			}
			if err := processOU(ctx, client, &childUnit); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			mu.Lock()
			ou.Children = append(ou.Children, childUnit)
			mu.Unlock()
		}(childOU)
	}

	// Collect all accounts with pagination
	var accounts []awstypes.Account
	nextToken = nil

	for {
		input := &organizations.ListAccountsForParentInput{
			ParentId: &ou.ID,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		output, err := client.ListAccountsForParent(ctx, input)
		if err != nil {
			return fmt.Errorf("failed to list accounts for %s: %w", ou.ID, err)
		}

		accounts = append(accounts, output.Accounts...)
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	for _, acct := range accounts {
		account := Account{
			ID:     *acct.Id,
			Name:   *acct.Name,
			Email:  *acct.Email,
			Status: string(acct.Status),
		}
		ou.Accounts = append(ou.Accounts, account)
		slog.Debug("Account found in OU:", "account", account)
	}

	wg.Wait()
	if len(errs) > 0 {
		return fmt.Errorf("errors occurred while processing OUs: %v", errs)
	}
	return nil
}

// collectPolicies retrieves all policies of the specified type and their content/targets concurrently.
func collectPolicies(ctx context.Context, client OrganizationsClient, policyType awstypes.PolicyType) ([]PolicyData, error) {
	slog.Debug("Collecting policies", "policyType", policyType)

	policies, err := listPolicies(ctx, client, policyType)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	var policyDataList []PolicyData
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, policy := range policies {
		wg.Add(1)
		go func(policy awstypes.PolicySummary) {
			defer wg.Done()
			slog.Debug("Processing policy", "policy", *policy.Name)

			rawContent, err := getPolicyContent(ctx, client, *policy.Id)
			if err != nil {
				slog.Warn("Failed to get policy content", "policy", *policy.Name, "error", err)
				return
			}
			slog.Debug("Raw policy content", "policy", *policy.Name, "content", rawContent)

			var policyContent types.Policy
			if err := json.Unmarshal([]byte(rawContent), &policyContent); err != nil {
				slog.Warn("Failed to unmarshal policy content", "policy", *policy.Name, "rawContent", rawContent, "error", err)
				return
			}
			slog.Debug("Successfully unmarshalled policy", "policy", *policy.Name, "content", policyContent)

			targets, err := listPolicyTargets(ctx, client, *policy.Id)
			if err != nil {
				slog.Warn("Failed to list policy targets", "policy", *policy.Name, "error", err)
				return
			}

			// Convert awstypes.PolicySummary to PolicySummaryRef at collection boundary
			policyData := PolicyData{
				PolicySummary: PolicySummaryRef{
					Arn:         policy.Arn,
					AwsManaged:  boolPtr(policy.AwsManaged),
					Description: policy.Description,
					Id:          policy.Id,
					Name:        policy.Name,
					Type:        policyTypeToString(policy.Type),
				},
				PolicyContent: policyContent,
				Targets:       targets,
			}

			mu.Lock()
			policyDataList = append(policyDataList, policyData)
			mu.Unlock()
		}(policy)
	}
	wg.Wait()

	slog.Info("Collected policies", "policies", len(policyDataList))
	return policyDataList, nil
}

// listPolicies retrieves all policies of a given type with pagination.
func listPolicies(ctx context.Context, client OrganizationsClient, policyType awstypes.PolicyType) ([]awstypes.PolicySummary, error) {
	var policies []awstypes.PolicySummary
	var nextToken *string

	for {
		input := &organizations.ListPoliciesInput{
			Filter: policyType,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		output, err := client.ListPolicies(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list policies: %w", err)
		}

		policies = append(policies, output.Policies...)
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	return policies, nil
}

// getPolicyContent retrieves the JSON content for a single policy.
func getPolicyContent(ctx context.Context, client OrganizationsClient, policyID string) (string, error) {
	input := &organizations.DescribePolicyInput{
		PolicyId: &policyID,
	}
	output, err := client.DescribePolicy(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to describe policy: %w", err)
	}
	return *output.Policy.Content, nil
}

// listPolicyTargets retrieves all targets for a policy with pagination.
func listPolicyTargets(ctx context.Context, client OrganizationsClient, policyID string) ([]PolicyTarget, error) {
	var targets []PolicyTarget
	var nextToken *string

	for {
		input := &organizations.ListTargetsForPolicyInput{
			PolicyId: &policyID,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		output, err := client.ListTargetsForPolicy(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list policy targets: %w", err)
		}

		for _, target := range output.Targets {
			targets = append(targets, PolicyTarget{
				TargetID: *target.TargetId,
				Name:     *target.Name,
				Type:     string(target.Type),
			})
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	return targets, nil
}

// BuildOrgPoliciesFromHierarchy constructs the complete OrgPolicies structure from the hierarchy and policy data.
// This is exported for testing purposes.
func BuildOrgPoliciesFromHierarchy(ou *OrgUnit, scps []PolicyData, rcps []PolicyData) *OrgPolicies {
	slog.Debug("Building OrgPolicies from OrgUnit hierarchy", "orgUnit", ou.ID)

	orgPolicies := &OrgPolicies{
		SCPs:    scps,
		RCPs:    rcps,
		Targets: []OrgPolicyTarget{},
	}

	targetToSCPs := mapTargetsToPolicies(scps)
	targetToRCPs := mapTargetsToPolicies(rcps)

	var processUnit func(unit *OrgUnit, parentSCPs []ParentPolicy, parentRCPs []ParentPolicy)
	processUnit = func(unit *OrgUnit, parentSCPs []ParentPolicy, parentRCPs []ParentPolicy) {
		// Pre-processing for null RCPs
		if targetToRCPs[unit.ID] == nil {
			targetToRCPs[unit.ID] = []string{}
		}

		// Add the current OrgUnit as a target
		orgPolicies.Targets = append(orgPolicies.Targets, OrgPolicyTarget{
			Name: unit.Name,
			ID:   unit.ID,
			Type: "OU",
			SCPs: OrgPolicyTargetPolicies{
				DirectPolicies: targetToSCPs[unit.ID],
				ParentPolicies: parentSCPs,
			},
			RCPs: OrgPolicyTargetPolicies{
				DirectPolicies: targetToRCPs[unit.ID],
				ParentPolicies: parentRCPs,
			},
		})

		parentSCPsForChildren := append(parentSCPs, ParentPolicy{
			Name:     unit.Name,
			ID:       unit.ID,
			Policies: targetToSCPs[unit.ID],
		})

		parentRCPsForChildren := append(parentRCPs, ParentPolicy{
			Name:     unit.Name,
			ID:       unit.ID,
			Policies: targetToRCPs[unit.ID],
		})

		// Recurse into children
		for _, child := range unit.Children {
			processUnit(&child, parentSCPsForChildren, parentRCPsForChildren)
		}

		// Add accounts as targets with account information
		for _, account := range unit.Accounts {
			orgPolicies.Targets = append(orgPolicies.Targets, OrgPolicyTarget{
				Name:    account.Name,
				ID:      account.ID,
				Type:    "ACCOUNT",
				Account: &account,
				SCPs: OrgPolicyTargetPolicies{
					DirectPolicies: targetToSCPs[account.ID],
					ParentPolicies: parentSCPsForChildren,
				},
				RCPs: OrgPolicyTargetPolicies{
					DirectPolicies: targetToRCPs[account.ID],
					ParentPolicies: parentRCPsForChildren,
				},
			})
		}
	}

	processUnit(ou, []ParentPolicy{}, []ParentPolicy{})
	return orgPolicies
}

// mapTargetsToPolicies creates a map from target IDs to policy ARNs.
func mapTargetsToPolicies(policies []PolicyData) map[string][]string {
	targetToPolicies := make(map[string][]string)

	for _, policy := range policies {
		for _, target := range policy.Targets {
			targetToPolicies[target.TargetID] = append(targetToPolicies[target.TargetID], *policy.PolicySummary.Arn)
		}
	}

	return targetToPolicies
}

// policyTypeToString converts awstypes.PolicyType to *string for PolicySummaryRef.
func policyTypeToString(pt awstypes.PolicyType) *string {
	s := string(pt)
	return &s
}

// boolPtr converts a bool to *bool for compatibility with PolicySummaryRef.
func boolPtr(b bool) *bool {
	return &b
}
