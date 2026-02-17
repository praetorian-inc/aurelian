//go:build integration

package recon

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockOrgPolicies builds an OrgPolicies via BuildOrgPoliciesFromHierarchy
// using anonymized data modeled on a real AWS Organization output.
// Org-policies requires management account access so we mock the output.
func mockOrgPolicies() *orgpolicies.OrgPolicies {
	str := func(s string) *string { return &s }

	fullAccessArn := "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"
	rcpFullAccessArn := "arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess"

	hierarchy := &orgpolicies.OrgUnit{
		ID:   "r-test",
		Name: "Root",
		Accounts: []orgpolicies.Account{
			{ID: "111111111111", Name: "test-sandbox", Email: "test@example.com", Status: "ACTIVE"},
		},
	}

	scps := []orgpolicies.PolicyData{
		{
			PolicySummary: orgpolicies.PolicySummaryRef{
				Arn: str(fullAccessArn), Name: str("FullAWSAccess"), Id: str("p-FullAWSAccess"),
			},
			PolicyContent: types.Policy{
				Version: "2012-10-17",
				Statement: &types.PolicyStatementList{
					{Effect: "Allow", Action: types.NewDynaString([]string{"*"}), Resource: types.NewDynaString([]string{"*"})},
				},
			},
			Targets: []orgpolicies.PolicyTarget{
				{TargetID: "r-test", Name: "Root", Type: "ROOT"},
				{TargetID: "111111111111", Name: "test-sandbox", Type: "ACCOUNT"},
			},
		},
	}

	rcps := []orgpolicies.PolicyData{
		{
			PolicySummary: orgpolicies.PolicySummaryRef{
				Arn: str(rcpFullAccessArn), Name: str("RCPFullAWSAccess"), Id: str("p-RCPFullAWSAccess"),
			},
			PolicyContent: types.Policy{
				Version: "2012-10-17",
				Statement: &types.PolicyStatementList{
					{Effect: "Allow", Action: types.NewDynaString([]string{"*"}), Resource: types.NewDynaString([]string{"*"})},
				},
			},
			Targets: []orgpolicies.PolicyTarget{
				{TargetID: "r-test", Name: "Root", Type: "ROOT"},
				{TargetID: "111111111111", Name: "test-sandbox", Type: "ACCOUNT"},
			},
		},
	}

	return orgpolicies.BuildOrgPoliciesFromHierarchy(hierarchy, scps, rcps)
}

func TestAWSOrgPolicies(t *testing.T) {
	orgPols := mockOrgPolicies()

	raw, err := json.Marshal(orgPols)
	require.NoError(t, err)

	var roundTripped orgpolicies.OrgPolicies
	require.NoError(t, json.Unmarshal(raw, &roundTripped))

	assert.Len(t, roundTripped.SCPs, 1)
	assert.Len(t, roundTripped.RCPs, 1)
	assert.Len(t, roundTripped.Targets, 2) // Root OU + account

	acct := orgPols.GetAccount("111111111111")
	require.NotNil(t, acct)
	assert.Equal(t, "test-sandbox", acct.Name)

	scpStmts := orgPols.GetAllScpPoliciesForTarget("111111111111")
	require.NotNil(t, scpStmts)
	require.NotEmpty(t, *scpStmts)

	rcpStmts := orgPols.GetAllRcpPoliciesForTarget("111111111111")
	require.NotNil(t, rcpStmts)
	require.NotEmpty(t, *rcpStmts)

	parentScps := orgPols.GetMergedParentScpsForTarget("111111111111")
	assert.Contains(t, parentScps, "r-test")

	parentRcps := orgPols.GetMergedParentRcpsForTarget("111111111111")
	assert.Contains(t, parentRcps, "r-test")

	assert.Nil(t, orgPols.GetAccount("999999999999"))
}
