package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	awstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&GetOrgPoliciesModule{})
}

// GetOrgPoliciesModule fetches AWS organization policies
type GetOrgPoliciesModule struct{}

func (m *GetOrgPoliciesModule) ID() string {
	return "get-orgpolicies"
}

func (m *GetOrgPoliciesModule) Name() string {
	return "AWS Get Organization Policies"
}

func (m *GetOrgPoliciesModule) Description() string {
	return "Get SCPs and RCPs of an AWS organization and the targets to which they are attached."
}

func (m *GetOrgPoliciesModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *GetOrgPoliciesModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GetOrgPoliciesModule) OpsecLevel() string {
	return "moderate"
}

func (m *GetOrgPoliciesModule) Authors() []string {
	return []string{"Andrew Chang"}
}

func (m *GetOrgPoliciesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListRoots.html",
		"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListOrganizationalUnitsForParent.html",
		"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccountsForParent.html",
		"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPolicies.html",
		"https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribePolicy.html",
		"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListTargetsForPolicy.html",
	}
}

func (m *GetOrgPoliciesModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "profile",
			Description: "AWS profile name",
			Type:        "string",
		},
		{
			Name:        "profile-dir",
			Description: "AWS profile directory",
			Type:        "string",
		},
	}
}

func (m *GetOrgPoliciesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get AWS config
	profile, _ := cfg.Args["profile"].(string)
	profileDir, _ := cfg.Args["profile-dir"].(string)

	var opts []*types.Option
	if profileDir != "" {
		opts = append(opts, &types.Option{
			Name:  "profile-dir",
			Value: profileDir,
		})
	}

	// Organizations is a global service, use us-east-1
	awsCfg, err := helpers.GetAWSCfg("us-east-1", profile, opts, "moderate")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Collect organization hierarchy
	orgHierarchy, err := m.collectOrganizationHierarchy(cfg.Context, awsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to collect organization hierarchy: %w", err)
	}

	// Collect SCPs and RCPs
	scps, err := m.collectPolicies(cfg.Context, awsCfg, awstypes.PolicyTypeServiceControlPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to collect SCPs: %w", err)
	}

	rcps, err := m.collectPolicies(cfg.Context, awsCfg, awstypes.PolicyTypeResourceControlPolicy)
	if err != nil {
		// RCPs might not be available in all accounts, log but don't fail
		if cfg.Verbose {
			fmt.Fprintf(cfg.Output, "Warning: failed to collect RCPs: %v\n", err)
		}
		rcps = []PolicyData{}
	}

	// Build final policies structure
	orgPolicies := m.buildOrgPoliciesFromHierarchy(orgHierarchy, scps, rcps)

	return []plugin.Result{
		{
			Data: orgPolicies,
			Metadata: map[string]any{
				"module":      "get-orgpolicies",
				"platform":    "aws",
				"opsec_level": "moderate",
			},
		},
	}, nil
}

// OrgUnit represents an organizational unit in the hierarchy
type OrgUnit struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Children []OrgUnit `json:"children"`
	Accounts []Account `json:"accounts"`
}

// Account represents an AWS account
type Account struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Status string `json:"status"`
}

// PolicyData contains policy details
type PolicyData struct {
	PolicySummary awstypes.PolicySummary `json:"policySummary"`
	PolicyContent types.Policy           `json:"policyContent"`
	Targets       []PolicyTarget         `json:"targets"`
}

// PolicyTarget represents a policy target
type PolicyTarget struct {
	TargetID string `json:"targetId"`
	Name     string `json:"name"`
	Type     string `json:"type"`
}

// OrgPolicies contains all organization policies
type OrgPolicies struct {
	SCPs    []PolicyData      `json:"scps"`
	RCPs    []PolicyData      `json:"rcps"`
	Targets []OrgPolicyTarget `json:"targets"`
}

// OrgPolicyTarget represents a target with associated policies
type OrgPolicyTarget struct {
	Name    string                  `json:"name"`
	ID      string                  `json:"id"`
	SCPs    OrgPolicyTargetPolicies `json:"scps"`
	RCPs    OrgPolicyTargetPolicies `json:"rcps"`
	Account *Account                `json:"account,omitempty"`
	Type    string                  `json:"type"`
}

// OrgPolicyTargetPolicies contains direct and parent policies
type OrgPolicyTargetPolicies struct {
	DirectPolicies []string       `json:"direct"`
	ParentPolicies []ParentPolicy `json:"parents"`
}

// ParentPolicy represents a parent policy
type ParentPolicy struct {
	Name     string   `json:"name"`
	ID       string   `json:"id"`
	Policies []string `json:"policies"`
}

func (m *GetOrgPoliciesModule) collectOrganizationHierarchy(ctx context.Context, awsCfg aws.Config) (*OrgUnit, error) {
	client := organizations.NewFromConfig(awsCfg)

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

	if err := m.processOU(ctx, client, &rootOU); err != nil {
		return nil, err
	}

	return &rootOU, nil
}

func (m *GetOrgPoliciesModule) processOU(ctx context.Context, client *organizations.Client, ou *OrgUnit) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	// List child OUs
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
			if err := m.processOU(ctx, client, &childUnit); err != nil {
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

	// List accounts in this OU
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
	}

	wg.Wait()
	if len(errs) > 0 {
		return fmt.Errorf("errors occurred while processing OUs: %v", errs)
	}

	return nil
}

func (m *GetOrgPoliciesModule) collectPolicies(ctx context.Context, awsCfg aws.Config, policyType awstypes.PolicyType) ([]PolicyData, error) {
	client := organizations.NewFromConfig(awsCfg)

	policies, err := m.listPolicies(ctx, client, policyType)
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

			rawContent, err := m.getPolicyContent(ctx, client, *policy.Id)
			if err != nil {
				return
			}

			var policyContent types.Policy
			if err := json.Unmarshal([]byte(rawContent), &policyContent); err != nil {
				return
			}

			targets, err := m.listPolicyTargets(ctx, client, *policy.Id)
			if err != nil {
				return
			}

			policyData := PolicyData{
				PolicySummary: policy,
				PolicyContent: policyContent,
				Targets:       targets,
			}

			mu.Lock()
			policyDataList = append(policyDataList, policyData)
			mu.Unlock()
		}(policy)
	}

	wg.Wait()
	return policyDataList, nil
}

func (m *GetOrgPoliciesModule) listPolicies(ctx context.Context, client *organizations.Client, policyType awstypes.PolicyType) ([]awstypes.PolicySummary, error) {
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

func (m *GetOrgPoliciesModule) getPolicyContent(ctx context.Context, client *organizations.Client, policyID string) (string, error) {
	input := &organizations.DescribePolicyInput{
		PolicyId: &policyID,
	}
	output, err := client.DescribePolicy(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to describe policy: %w", err)
	}
	return *output.Policy.Content, nil
}

func (m *GetOrgPoliciesModule) listPolicyTargets(ctx context.Context, client *organizations.Client, policyID string) ([]PolicyTarget, error) {
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

func (m *GetOrgPoliciesModule) buildOrgPoliciesFromHierarchy(ou *OrgUnit, scps []PolicyData, rcps []PolicyData) *OrgPolicies {
	orgPolicies := &OrgPolicies{
		SCPs:    scps,
		RCPs:    rcps,
		Targets: []OrgPolicyTarget{},
	}

	targetToSCPs := mapTargetsToPolicies(scps)
	targetToRCPs := mapTargetsToPolicies(rcps)

	var processUnit func(unit *OrgUnit, parentSCPs []ParentPolicy, parentRCPs []ParentPolicy)
	processUnit = func(unit *OrgUnit, parentSCPs []ParentPolicy, parentRCPs []ParentPolicy) {
		if targetToRCPs[unit.ID] == nil {
			targetToRCPs[unit.ID] = []string{}
		}

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

		for _, child := range unit.Children {
			processUnit(&child, parentSCPsForChildren, parentRCPsForChildren)
		}

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

func mapTargetsToPolicies(policies []PolicyData) map[string][]string {
	targetToPolicies := make(map[string][]string)

	for _, policy := range policies {
		for _, target := range policy.Targets {
			targetToPolicies[target.TargetID] = append(targetToPolicies[target.TargetID], *policy.PolicySummary.Arn)
		}
	}

	return targetToPolicies
}
