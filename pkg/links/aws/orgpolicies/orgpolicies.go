package orgpolicies

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/organizations"
	awstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go/aws"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSOrganizationPolicies struct {
	*base.AwsReconBaseLink
}

type OrgUnit struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Children []OrgUnit `json:"children"`
	Accounts []Account `json:"accounts"`
}

type Account struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Status string `json:"status"`
}

type PolicyData struct {
	PolicySummary awstypes.PolicySummary `json:"policySummary"`
	PolicyContent types.Policy           `json:"policyContent"`
	Targets       []PolicyTarget         `json:"targets"`
}

type PolicyTarget struct {
	TargetID string `json:"targetId"`
	Name     string `json:"name"`
	Type     string `json:"type"`
}

type OrgPolicies struct {
	SCPs    []PolicyData      `json:"scps"`
	RCPs    []PolicyData      `json:"rcps"`
	Targets []OrgPolicyTarget `json:"targets"`
}

func (o *OrgPolicies) GetAccount(accountID string) *Account {
	for _, target := range o.Targets {
		if target.Type == "ACCOUNT" && target.Account != nil && target.Account.ID == accountID {
			return target.Account
		}
	}
	return nil
}

func (o *OrgPolicies) GetPolicyForTarget(accountID string) *OrgPolicyTarget {
	for _, target := range o.Targets {
		if target.Account != nil && target.Account.ID == accountID {
			return &target
		}
	}
	return nil
}

func (o *OrgPolicies) GetPolicyContent(policyArn, policyType string) *types.Policy {
	switch policyType {
	case "scps":
		for _, policy := range o.SCPs {
			if *policy.PolicySummary.Arn == policyArn {
				return &policy.PolicyContent
			}
		}
	case "rcps":
		for _, policy := range o.RCPs {
			if *policy.PolicySummary.Arn == policyArn {
				return &policy.PolicyContent
			}
		}
	}
	return nil
}

func (o *OrgPolicies) GetDirectScpStatementsForTarget(accountID string) *types.PolicyStatementList {
	orgPolicyTarget := o.GetPolicyForTarget(accountID)
	if orgPolicyTarget == nil {
		return nil
	}

	var psl types.PolicyStatementList
	for _, policy := range orgPolicyTarget.SCPs.DirectPolicies {
		if content := o.GetPolicyContent(policy, "scps"); content != nil {
			for _, stmt := range *content.Statement {
				stmt.OriginArn = policy
				psl = append(psl, stmt)
			}
		}
	}

	return &psl
}

func (o *OrgPolicies) GetParentScpStatementsForTarget(accountID string) *types.PolicyStatementList {
	orgPolicyTarget := o.GetPolicyForTarget(accountID)
	if orgPolicyTarget == nil {
		return nil
	}

	var psl types.PolicyStatementList
	for _, parent := range orgPolicyTarget.SCPs.ParentPolicies {
		for _, policy := range parent.Policies {
			if content := o.GetPolicyContent(policy, "scps"); content != nil {
				for _, stmt := range *content.Statement {
					stmt.OriginArn = policy
					psl = append(psl, stmt)
				}
			}
		}
	}

	return &psl
}

func (o *OrgPolicies) GetMergedParentScpsForTarget(accountID string) map[string]*types.PolicyStatementList {
	orgPolicyTarget := o.GetPolicyForTarget(accountID)
	if orgPolicyTarget == nil {
		return nil
	}

	// Create map to store merged policies by parent ID
	mergedPolicies := make(map[string]*types.PolicyStatementList)

	// Group policies by parent
	for _, parent := range orgPolicyTarget.SCPs.ParentPolicies {
		var psl types.PolicyStatementList
		for _, policy := range parent.Policies {
			if content := o.GetPolicyContent(policy, "scps"); content != nil {
				for _, stmt := range *content.Statement {
					stmt.OriginArn = policy
					psl = append(psl, stmt)
				}
			}
		}
		if len(psl) > 0 {
			mergedPolicies[parent.ID] = &psl
		}
	}

	return mergedPolicies
}

func (o *OrgPolicies) GetMergedParentRcpsForTarget(accountID string) map[string]*types.PolicyStatementList {
	orgPolicyTarget := o.GetPolicyForTarget(accountID)
	if orgPolicyTarget == nil {
		return nil
	}

	mergedPolicies := make(map[string]*types.PolicyStatementList)

	for _, parent := range orgPolicyTarget.RCPs.ParentPolicies {
		var psl types.PolicyStatementList
		for _, policy := range parent.Policies {
			if content := o.GetPolicyContent(policy, "rcps"); content != nil {
				for _, stmt := range *content.Statement {
					stmt.OriginArn = policy
					psl = append(psl, stmt)
				}
			}
		}
		if len(psl) > 0 {
			mergedPolicies[parent.ID] = &psl
		}
	}

	return mergedPolicies
}

func (o *OrgPolicies) GetAllScpPoliciesForTarget(accountID string) *types.PolicyStatementList {
	orgPolicyTarget := o.GetPolicyForTarget(accountID)
	if orgPolicyTarget == nil {
		return nil
	}

	var psl types.PolicyStatementList
	// Get direct SCP statements
	if direct := o.GetDirectScpStatementsForTarget(accountID); direct != nil {
		psl = append(psl, *direct...)
	}
	// Get parent SCP statements
	if parent := o.GetParentScpStatementsForTarget(accountID); parent != nil {
		psl = append(psl, *parent...)
	}

	return &psl
}

func (o *OrgPolicies) GetAllRcpPoliciesForTarget(accountID string) *types.PolicyStatementList {
	orgPolicyTarget := o.GetPolicyForTarget(accountID)
	if orgPolicyTarget == nil {
		return nil
	}

	var psl types.PolicyStatementList
	// Get direct RCP statements
	if direct := o.GetDirectRcpStatementsForTarget(accountID); direct != nil {
		psl = append(psl, *direct...)
	}
	// Get parent RCP statements
	if parent := o.GetParentRcpStatementsForTarget(accountID); parent != nil {
		psl = append(psl, *parent...)
	}

	return &psl
}

func (o *OrgPolicies) GetDirectRcpStatementsForTarget(accountID string) *types.PolicyStatementList {
	orgPolicyTarget := o.GetPolicyForTarget(accountID)
	if orgPolicyTarget == nil {
		return nil
	}

	var psl types.PolicyStatementList
	for _, policy := range orgPolicyTarget.RCPs.DirectPolicies {
		if content := o.GetPolicyContent(policy, "rcps"); content != nil {
			for _, stmt := range *content.Statement {
				stmt.OriginArn = policy
				psl = append(psl, stmt)
			}
		}
	}

	return &psl
}

func (o *OrgPolicies) GetParentRcpStatementsForTarget(accountID string) *types.PolicyStatementList {
	orgPolicyTarget := o.GetPolicyForTarget(accountID)
	if orgPolicyTarget == nil {
		return nil
	}

	var psl types.PolicyStatementList
	for _, parent := range orgPolicyTarget.RCPs.ParentPolicies {
		for _, policy := range parent.Policies {
			if content := o.GetPolicyContent(policy, "rcps"); content != nil {
				for _, stmt := range *content.Statement {
					stmt.OriginArn = policy
					psl = append(psl, stmt)
				}
			}
		}
	}

	return &psl
}

// https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html
// For a permission to be allowed for a specific account, there must be an explicit Allow statement at
// every level from the root through each OU in the direct path to the account (including the target account itself).
func (o *OrgPolicies) TargetHasParentAllowed(targetID string) bool {
	orgPolicyTarget := o.GetPolicyForTarget(targetID)
	if orgPolicyTarget == nil {
		return false
	}

	return false
}

type OrgPolicyTarget struct {
	Name    string                  `json:"name"`
	ID      string                  `json:"id"`
	SCPs    OrgPolicyTargetPolicies `json:"scps"`
	RCPs    OrgPolicyTargetPolicies `json:"rcps"`
	Account *Account                `json:"account,omitempty"`
	Type    string                  `json:"type"`
}

type OrgPolicyTargetPolicies struct {
	DirectPolicies []string       `json:"direct"` // arns
	ParentPolicies []ParentPolicy `json:"parents"`
}

type ParentPolicy struct {
	Name     string   `json:"name"`
	ID       string   `json:"id"`
	Policies []string `json:"policies"` // arns
}

func NewAWSOrganizationPolicies(configs ...cfg.Config) chain.Link {
	slog.Debug("Creating AWSOrganizationPolicies link")
	ad := &AWSOrganizationPolicies{}
	slog.Debug("Config:", "configs", configs)
	ad.AwsReconBaseLink = base.NewAwsReconBaseLink(ad, configs...)
	return ad
}

func (ad *AWSOrganizationPolicies) Initialize() error {
	slog.Debug("Initializing AWSOrganizationPolicies")
	if err := ad.AwsReconBaseLink.Initialize(); err != nil {
		return err
	}
	return nil
}

func (ad *AWSOrganizationPolicies) Process(_ string) error {
	// the Process() method signature requires an input even if it is unused
	slog.Debug("Begin processing AWSOrganizationPolicies", "profile", ad.Profile)

	org_hierarchy, error := ad.CollectOrganizationHierarchy()
	if error != nil {
		slog.Error("Error collecting organization hierarchy", "error", error)
		return error
	}

	scps, error := ad.CollectPolicies(awstypes.PolicyTypeServiceControlPolicy)
	if error != nil {
		slog.Error("Error collecting organization SCPs", "error", error)
		return error
	}

	rcps, error := ad.CollectPolicies(awstypes.PolicyTypeResourceControlPolicy)
	if error != nil {
		slog.Error("Error collecting organization RCPs", "error", error)
		return error
	}

	if rcps == nil {
		rcps = []PolicyData{}
	}

	org_policies := ad.BuildOrgPoliciesFromHierarchy(org_hierarchy, scps, rcps)

	ad.Send(org_policies)
	return nil
}

func (ad *AWSOrganizationPolicies) BuildOrgPoliciesFromHierarchy(ou *OrgUnit, scps []PolicyData, rcps []PolicyData) *OrgPolicies {
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
		// some pre-processing for null RCPs
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

func (a *AWSOrganizationPolicies) CollectOrganizationHierarchy() (*OrgUnit, error) {
	slog.Debug("Collecting Organization Hierarchy", "profile", a.Profile)
	print("Collecting Organization Hierarchy", "profile", a.Profile)

	// We'll use us-east-1 for IAM since it's a global service
	region := "us-east-1"

	slog.Debug("Collecting Organization Hierarchy: Set region to ", "region", region)

	config, err := a.GetConfigWithRuntimeArgs(region)
	if err != nil {
		slog.Error("Failed to create AWS config", "error", err)
		return nil, err
	}

	client := organizations.NewFromConfig(config)
	roots, err := client.ListRoots(context.TODO(), &organizations.ListRootsInput{})
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
	if err := processOU(client, &rootOU); err != nil {
		return nil, err
	}
	return &rootOU, nil
}

func processOU(client *organizations.Client, ou *OrgUnit) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	var childOUs []awstypes.OrganizationalUnit
	var nextToken *string

	for {
		input := &organizations.ListOrganizationalUnitsForParentInput{
			ParentId: &ou.ID,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}
		output, err := client.ListOrganizationalUnitsForParent(context.TODO(), input)
		if err != nil {
			return fmt.Errorf("failed to list child OUs for %s: %w", ou.ID, err)
		}
		childOUs = append(childOUs, output.OrganizationalUnits...)
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	for _, childOU := range childOUs {
		wg.Add(1)
		go func(child awstypes.OrganizationalUnit) {
			defer wg.Done()
			childUnit := OrgUnit{
				ID:   *child.Id,
				Name: *child.Name,
			}
			if err := processOU(client, &childUnit); err != nil {
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

	var accounts []awstypes.Account
	nextToken = nil
	for {
		input := &organizations.ListAccountsForParentInput{
			ParentId: &ou.ID,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}
		output, err := client.ListAccountsForParent(context.TODO(), input)
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

func (a *AWSOrganizationPolicies) CollectPolicies(policyType awstypes.PolicyType) ([]PolicyData, error) {
	slog.Debug("Getting Account Authorization Details", "profile", a.Profile)

	// We'll use us-east-1 for IAM since it's a global service
	region := "us-east-1"

	slog.Debug("Getting Account Authorization Details: Set region to ", "region", region)

	config, err := a.GetConfigWithRuntimeArgs(region)
	if err != nil {
		slog.Error("Failed to create AWS config", "error", err)
		return nil, err
	}

	client := organizations.NewFromConfig(config)
	var policyDataList []PolicyData
	policies, err := listPolicies(client, policyType)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, policy := range policies {
		wg.Add(1)
		go func(policy awstypes.PolicySummary) {
			defer wg.Done()
			slog.Debug("Processing policy", "policy", *policy.Name)

			rawContent, err := getPolicyContent(client, *policy.Id)
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
			targets, err := listPolicyTargets(client, *policy.Id)
			if err != nil {
				slog.Warn("Failed to list policy targets", "policy", *policy.Name, "error", err)
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

	slog.Info("Collected policies", "policies", len(policyDataList))
	return policyDataList, nil
}

func listPolicies(client *organizations.Client, policyType awstypes.PolicyType) ([]awstypes.PolicySummary, error) {
	var policies []awstypes.PolicySummary
	var nextToken *string
	for {
		input := &organizations.ListPoliciesInput{
			Filter: policyType,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}
		output, err := client.ListPolicies(context.TODO(), input)
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

func getPolicyContent(client *organizations.Client, policyID string) (string, error) {
	input := &organizations.DescribePolicyInput{
		PolicyId: &policyID,
	}
	output, err := client.DescribePolicy(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("failed to describe policy: %w", err)
	}
	return *output.Policy.Content, nil
}

func listPolicyTargets(client *organizations.Client, policyID string) ([]PolicyTarget, error) {
	var targets []PolicyTarget
	var nextToken *string
	for {
		input := &organizations.ListTargetsForPolicyInput{
			PolicyId: &policyID,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}
		output, err := client.ListTargetsForPolicy(context.TODO(), input)
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

func mapTargetsToPolicies(policies []PolicyData) map[string][]string {
	targetToPolicies := make(map[string][]string)

	for _, policy := range policies {
		for _, target := range policy.Targets {
			targetToPolicies[target.TargetID] = append(targetToPolicies[target.TargetID], *policy.PolicySummary.Arn)
		}
	}

	return targetToPolicies
}

// Add this function to create a default full access policy
func NewDefaultOrgPolicies() *OrgPolicies {
	return &OrgPolicies{
		SCPs: []PolicyData{
			{
				PolicySummary: awstypes.PolicySummary{
					Name: aws.String("FullAWSAccess"),
					Id:   aws.String("p-FullAWSAccess"),
					Arn:  aws.String("arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"),
				},
				PolicyContent: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{
							Effect:   "Allow",
							Action:   types.NewDynaString([]string{"*"}),
							Resource: types.NewDynaString([]string{"*"}),
						},
					},
				},
				Targets: []PolicyTarget{
					{
						TargetID: "r-root", // Root OU ID
						Name:     "Root",
						Type:     "ROOT",
					},
				},
			},
		},
		RCPs: []PolicyData{}, // Empty RCPs as default
		Targets: []OrgPolicyTarget{
			{
				Name: "Root",
				ID:   "r-root",
				Type: "OU",
				SCPs: OrgPolicyTargetPolicies{
					DirectPolicies: []string{"arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"},
					ParentPolicies: []ParentPolicy{},
				},
				RCPs: OrgPolicyTargetPolicies{
					DirectPolicies: []string{},
					ParentPolicies: []ParentPolicy{},
				},
			},
		},
	}
}
