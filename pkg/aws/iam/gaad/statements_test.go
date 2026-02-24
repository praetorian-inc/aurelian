package gaad

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// copyStatementsWithOrigin
// ---------------------------------------------------------------------------

func TestCopyStatementsWithOrigin_NilInput(t *testing.T) {
	result := copyStatementsWithOrigin(nil, "arn:aws:iam::111122223333:user/alice")
	assert.Nil(t, result)
}

func TestCopyStatementsWithOrigin_EmptyInput(t *testing.T) {
	empty := &types.PolicyStatementList{}
	result := copyStatementsWithOrigin(empty, "arn:aws:iam::111122223333:user/alice")
	assert.Nil(t, result)
}

func TestCopyStatementsWithOrigin_SetsOriginArn(t *testing.T) {
	action := types.DynaString{"s3:GetObject"}
	resource := types.DynaString{"*"}
	stmts := &types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   &action,
			Resource: &resource,
		},
		{
			Effect:   "Deny",
			Action:   &action,
			Resource: &resource,
		},
	}

	origin := "arn:aws:iam::111122223333:policy/MyPolicy"
	result := copyStatementsWithOrigin(stmts, origin)

	require.Len(t, result, 2)
	assert.Equal(t, origin, result[0].OriginArn)
	assert.Equal(t, origin, result[1].OriginArn)

	// Verify the original statements are not mutated
	assert.Equal(t, "", (*stmts)[0].OriginArn)
	assert.Equal(t, "", (*stmts)[1].OriginArn)
}

func TestCopyStatementsWithOrigin_PreservesStatementFields(t *testing.T) {
	action := types.DynaString{"iam:PassRole"}
	resource := types.DynaString{"arn:aws:iam::111122223333:role/*"}
	stmts := &types.PolicyStatementList{
		{
			Sid:      "AllowPassRole",
			Effect:   "Allow",
			Action:   &action,
			Resource: &resource,
		},
	}

	result := copyStatementsWithOrigin(stmts, "some-origin")

	require.Len(t, result, 1)
	assert.Equal(t, "AllowPassRole", result[0].Sid)
	assert.Equal(t, "Allow", result[0].Effect)
	assert.Equal(t, &action, result[0].Action)
	assert.Equal(t, &resource, result[0].Resource)
}

// ---------------------------------------------------------------------------
// collectInlineStatements
// ---------------------------------------------------------------------------

func TestCollectInlineStatements_Empty(t *testing.T) {
	result := collectInlineStatements(nil, "arn:aws:iam::111122223333:user/alice")
	assert.Nil(t, result)

	result = collectInlineStatements([]types.InlinePolicy{}, "arn:aws:iam::111122223333:user/alice")
	assert.Nil(t, result)
}

func TestCollectInlineStatements_NilPolicyDocument(t *testing.T) {
	policies := []types.InlinePolicy{
		{
			PolicyName:     "NilStmtPolicy",
			PolicyDocument: types.Policy{Version: "2012-10-17"},
		},
	}
	result := collectInlineStatements(policies, "some-origin")
	assert.Nil(t, result)
}

func TestCollectInlineStatements_WithStatements(t *testing.T) {
	action := types.DynaString{"s3:GetObject"}
	resource := types.DynaString{"*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action, Resource: &resource},
	}

	policies := []types.InlinePolicy{
		{
			PolicyName: "Policy1",
			PolicyDocument: types.Policy{
				Version:   "2012-10-17",
				Statement: &stmts,
			},
		},
	}

	originArn := "arn:aws:iam::111122223333:user/alice"
	result := collectInlineStatements(policies, originArn)

	require.Len(t, result, 1)
	assert.Equal(t, originArn, result[0].OriginArn)
	assert.Equal(t, "Allow", result[0].Effect)
}

func TestCollectInlineStatements_MultiplePolicies(t *testing.T) {
	action1 := types.DynaString{"s3:GetObject"}
	resource1 := types.DynaString{"*"}
	stmts1 := types.PolicyStatementList{
		{Effect: "Allow", Action: &action1, Resource: &resource1},
	}

	action2 := types.DynaString{"ec2:DescribeInstances"}
	resource2 := types.DynaString{"*"}
	stmts2 := types.PolicyStatementList{
		{Effect: "Allow", Action: &action2, Resource: &resource2},
	}

	policies := []types.InlinePolicy{
		{PolicyName: "P1", PolicyDocument: types.Policy{Version: "2012-10-17", Statement: &stmts1}},
		{PolicyName: "P2", PolicyDocument: types.Policy{Version: "2012-10-17", Statement: &stmts2}},
	}

	result := collectInlineStatements(policies, "origin")
	require.Len(t, result, 2)
}

// ---------------------------------------------------------------------------
// collectManagedPolicyStatements
// ---------------------------------------------------------------------------

func TestCollectManagedPolicyStatements_Empty(t *testing.T) {
	state := buildMinimalState()
	result := collectManagedPolicyStatements(state, nil)
	assert.Nil(t, result)

	result = collectManagedPolicyStatements(state, []types.ManagedPolicy{})
	assert.Nil(t, result)
}

func TestCollectManagedPolicyStatements_PolicyNotFound(t *testing.T) {
	state := buildMinimalState()
	policies := []types.ManagedPolicy{
		{PolicyName: "DoesNotExist", PolicyArn: "arn:aws:iam::111122223333:policy/Nonexistent"},
	}
	result := collectManagedPolicyStatements(state, policies)
	assert.Nil(t, result)
}

func TestCollectManagedPolicyStatements_PolicyFound(t *testing.T) {
	action := types.DynaString{"iam:PassRole"}
	resource := types.DynaString{"*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action, Resource: &resource},
	}

	policyArn := "arn:aws:iam::111122223333:policy/TestPolicy"
	gaad := types.NewAuthorizationAccountDetails("", nil, nil, nil, []types.ManagedPolicyDetail{
			{
				PolicyName: "TestPolicy",
				Arn:        policyArn,
				PolicyVersionList: []types.PolicyVersion{
					{
						VersionId:        "v1",
						IsDefaultVersion: true,
						Document: types.Policy{
							Version:   "2012-10-17",
							Statement: &stmts,
						},
					},
				},
			},
		},
	)
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	attached := []types.ManagedPolicy{
		{PolicyName: "TestPolicy", PolicyArn: policyArn},
	}
	result := collectManagedPolicyStatements(state, attached)

	require.Len(t, result, 1)
	assert.Equal(t, policyArn, result[0].OriginArn)
}

func TestCollectManagedPolicyStatements_PolicyWithNoDefaultVersion(t *testing.T) {
	policyArn := "arn:aws:iam::111122223333:policy/NoDefault"
	gaad := types.NewAuthorizationAccountDetails("", nil, nil, nil, []types.ManagedPolicyDetail{
			{
				PolicyName: "NoDefault",
				Arn:        policyArn,
				PolicyVersionList: []types.PolicyVersion{
					{
						VersionId:        "v1",
						IsDefaultVersion: false,
						Document:         types.Policy{Version: "2012-10-17"},
					},
				},
			},
		},
	)
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	attached := []types.ManagedPolicy{
		{PolicyName: "NoDefault", PolicyArn: policyArn},
	}
	result := collectManagedPolicyStatements(state, attached)
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// collectBoundaryStatements
// ---------------------------------------------------------------------------

func TestCollectBoundaryStatements_ZeroValue(t *testing.T) {
	state := buildMinimalState()
	result := collectBoundaryStatements(state, types.ManagedPolicy{})
	assert.Nil(t, result)
}

func TestCollectBoundaryStatements_PolicyNotFound(t *testing.T) {
	state := buildMinimalState()
	result := collectBoundaryStatements(state, types.ManagedPolicy{
		PolicyName: "Missing",
		PolicyArn:  "arn:aws:iam::111122223333:policy/Missing",
	})
	assert.Nil(t, result)
}

func TestCollectBoundaryStatements_Found(t *testing.T) {
	action := types.DynaString{"s3:*"}
	resource := types.DynaString{"*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action, Resource: &resource},
	}

	boundaryArn := "arn:aws:iam::111122223333:policy/Boundary"
	gaad := types.NewAuthorizationAccountDetails("", nil, nil, nil, []types.ManagedPolicyDetail{
			{
				PolicyName: "Boundary",
				Arn:        boundaryArn,
				PolicyVersionList: []types.PolicyVersion{
					{
						VersionId:        "v1",
						IsDefaultVersion: true,
						Document: types.Policy{
							Version:   "2012-10-17",
							Statement: &stmts,
						},
					},
				},
			},
		},
	)
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	result := collectBoundaryStatements(state, types.ManagedPolicy{
		PolicyName: "Boundary",
		PolicyArn:  boundaryArn,
	})

	require.Len(t, result, 1)
	assert.Equal(t, boundaryArn, result[0].OriginArn)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func buildMinimalState() *AnalyzerMemoryState {
	gaad := types.NewAuthorizationAccountDetails("", nil, nil, nil, nil)
	return NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), []output.AWSResource{})
}
