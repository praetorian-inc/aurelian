package orgpolicies

import (
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// PolicySummaryRef replaces awstypes.PolicySummary to avoid pulling AWS SDK
// into the types package. Field names match AWS SDK for JSON serialization.
type PolicySummaryRef struct {
	Arn         *string
	AwsManaged  *bool
	Description *string
	Id          *string
	Name        *string
	Type        *string // PolicyType enum as string
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
	PolicySummary PolicySummaryRef `json:"policySummary"`
	PolicyContent types.Policy     `json:"policyContent"`
	Targets       []PolicyTarget   `json:"targets"`
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

	mergedPolicies := make(map[string]*types.PolicyStatementList)

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
	if direct := o.GetDirectScpStatementsForTarget(accountID); direct != nil {
		psl = append(psl, *direct...)
	}
	if parent := o.GetParentScpStatementsForTarget(accountID); parent != nil {
		psl = append(psl, *parent...)
	}

	return &psl
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
	DirectPolicies []string       `json:"direct"`
	ParentPolicies []ParentPolicy `json:"parents"`
}

type ParentPolicy struct {
	Name     string   `json:"name"`
	ID       string   `json:"id"`
	Policies []string `json:"policies"`
}

func (o *OrgPolicies) GetAllRcpPoliciesForTarget(accountID string) *types.PolicyStatementList {
	orgPolicyTarget := o.GetPolicyForTarget(accountID)
	if orgPolicyTarget == nil {
		return nil
	}
	var psl types.PolicyStatementList
	if direct := o.GetDirectRcpStatementsForTarget(accountID); direct != nil {
		psl = append(psl, *direct...)
	}
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

func (o *OrgPolicies) TargetHasParentAllowed(targetID string) bool {
	orgPolicyTarget := o.GetPolicyForTarget(targetID)
	if orgPolicyTarget == nil {
		return false
	}
	return false
}

// NewDefaultOrgPolicies creates a default OrgPolicies with full AWS access
func NewDefaultOrgPolicies() *OrgPolicies {
	fullAccessArn := "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"
	return &OrgPolicies{
		SCPs: []PolicyData{
			{
				PolicySummary: PolicySummaryRef{
					Name: strPtr("FullAWSAccess"),
					Id:   strPtr("p-FullAWSAccess"),
					Arn:  strPtr(fullAccessArn),
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
						TargetID: "r-root",
						Name:     "Root",
						Type:     "ROOT",
					},
				},
			},
		},
		RCPs: []PolicyData{},
		Targets: []OrgPolicyTarget{
			{
				Name: "Root",
				ID:   "r-root",
				Type: "OU",
				SCPs: OrgPolicyTargetPolicies{
					DirectPolicies: []string{fullAccessArn},
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

func strPtr(s string) *string {
	return &s
}
