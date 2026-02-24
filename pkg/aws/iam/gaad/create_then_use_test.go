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
// newPermissionIndex
// ---------------------------------------------------------------------------

func TestNewPermissionIndex_Empty(t *testing.T) {
	idx := newPermissionIndex(nil)
	assert.NotNil(t, idx.principalResources)
	assert.Len(t, idx.principalResources, 0)
}

func TestNewPermissionIndex_PopulatesCorrectly(t *testing.T) {
	results := []output.AWSIAMRelationship{
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:user/alice"}},
			Resource:  output.AWSResource{ARN: "arn:aws:s3:::my-bucket"},
			Action:    "s3:GetObject",
		},
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:user/alice"}},
			Resource:  output.AWSResource{ARN: "arn:aws:s3:::my-bucket"},
			Action:    "s3:PutObject",
		},
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:role/test-role"}},
			Resource:  output.AWSResource{ARN: "arn:aws:lambda:us-east-1:111122223333:function:my-func"},
			Action:    "lambda:InvokeFunction",
		},
	}

	idx := newPermissionIndex(results)
	assert.Len(t, idx.principalResources, 2, "Expected two distinct principals")
	assert.Len(t, idx.principalResources["arn:aws:iam::111122223333:user/alice"], 1, "Expected one resource for alice")
	assert.Len(t, idx.principalResources["arn:aws:iam::111122223333:user/alice"]["arn:aws:s3:::my-bucket"], 2, "Expected two actions for alice on my-bucket")
}

// ---------------------------------------------------------------------------
// hasActionOnResource
// ---------------------------------------------------------------------------

func TestHasActionOnResource(t *testing.T) {
	results := []output.AWSIAMRelationship{
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: "user-a"}},
			Resource:  output.AWSResource{ARN: "resource-1"},
			Action:    "s3:GetObject",
		},
	}
	idx := newPermissionIndex(results)

	assert.True(t, idx.hasActionOnResource("user-a", "s3:GetObject", "resource-1"))
	assert.False(t, idx.hasActionOnResource("user-a", "s3:PutObject", "resource-1"))
	assert.False(t, idx.hasActionOnResource("user-a", "s3:GetObject", "resource-2"))
	assert.False(t, idx.hasActionOnResource("user-b", "s3:GetObject", "resource-1"))
}

// ---------------------------------------------------------------------------
// hasActionOnAnyResource
// ---------------------------------------------------------------------------

func TestHasActionOnAnyResource(t *testing.T) {
	results := []output.AWSIAMRelationship{
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: "user-a"}},
			Resource:  output.AWSResource{ARN: "resource-1"},
			Action:    "s3:GetObject",
		},
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: "user-a"}},
			Resource:  output.AWSResource{ARN: "resource-2"},
			Action:    "s3:PutObject",
		},
	}
	idx := newPermissionIndex(results)

	assert.True(t, idx.hasActionOnAnyResource("user-a", "s3:GetObject"))
	assert.True(t, idx.hasActionOnAnyResource("user-a", "s3:PutObject"))
	assert.False(t, idx.hasActionOnAnyResource("user-a", "s3:DeleteObject"))
	assert.False(t, idx.hasActionOnAnyResource("user-b", "s3:GetObject"))
}

// ---------------------------------------------------------------------------
// stmtAllowsAction
// ---------------------------------------------------------------------------

func TestStmtAllowsAction_AllowWithMatchingAction(t *testing.T) {
	action := types.DynaString{"codebuild:CreateProject"}
	stmt := types.PolicyStatement{
		Effect: "Allow",
		Action: &action,
	}
	assert.True(t, stmtAllowsAction(&stmt, "codebuild:CreateProject"))
}

func TestStmtAllowsAction_AllowWithWildcard(t *testing.T) {
	action := types.DynaString{"codebuild:*"}
	stmt := types.PolicyStatement{
		Effect: "Allow",
		Action: &action,
	}
	assert.True(t, stmtAllowsAction(&stmt, "codebuild:CreateProject"))
}

func TestStmtAllowsAction_AllowWithStarWildcard(t *testing.T) {
	action := types.DynaString{"*"}
	stmt := types.PolicyStatement{
		Effect: "Allow",
		Action: &action,
	}
	assert.True(t, stmtAllowsAction(&stmt, "codebuild:CreateProject"))
}

func TestStmtAllowsAction_DenyDoesNotMatch(t *testing.T) {
	action := types.DynaString{"codebuild:CreateProject"}
	stmt := types.PolicyStatement{
		Effect: "Deny",
		Action: &action,
	}
	assert.False(t, stmtAllowsAction(&stmt, "codebuild:CreateProject"))
}

func TestStmtAllowsAction_NonMatchingAction(t *testing.T) {
	action := types.DynaString{"s3:GetObject"}
	stmt := types.PolicyStatement{
		Effect: "Allow",
		Action: &action,
	}
	assert.False(t, stmtAllowsAction(&stmt, "codebuild:CreateProject"))
}

func TestStmtAllowsAction_NotAction_NotExcluded(t *testing.T) {
	notAction := types.DynaString{"iam:*"}
	stmt := types.PolicyStatement{
		Effect:    "Allow",
		NotAction: &notAction,
	}
	// codebuild:CreateProject is not excluded by NotAction iam:*, so should match
	assert.True(t, stmtAllowsAction(&stmt, "codebuild:CreateProject"))
}

func TestStmtAllowsAction_NotAction_Excluded(t *testing.T) {
	notAction := types.DynaString{"codebuild:*"}
	stmt := types.PolicyStatement{
		Effect:    "Allow",
		NotAction: &notAction,
	}
	// codebuild:CreateProject is excluded by NotAction codebuild:*
	assert.False(t, stmtAllowsAction(&stmt, "codebuild:CreateProject"))
}

func TestStmtAllowsAction_NilActionAndNilNotAction(t *testing.T) {
	stmt := types.PolicyStatement{
		Effect: "Allow",
	}
	assert.False(t, stmtAllowsAction(&stmt, "codebuild:CreateProject"))
}

// ---------------------------------------------------------------------------
// resourcePatternsOverlap
// ---------------------------------------------------------------------------

func TestResourcePatternsOverlap_BothWildcard(t *testing.T) {
	assert.True(t, resourcePatternsOverlap([]string{"*"}, []string{"*"}))
}

func TestResourcePatternsOverlap_OneWildcard(t *testing.T) {
	assert.True(t, resourcePatternsOverlap(
		[]string{"arn:aws:codebuild:us-east-1:111122223333:project/*"},
		[]string{"*"},
	))
}

func TestResourcePatternsOverlap_CompatibleARNs(t *testing.T) {
	assert.True(t, resourcePatternsOverlap(
		[]string{"arn:aws:codebuild:us-east-1:111122223333:project/*"},
		[]string{"arn:aws:codebuild:us-east-1:111122223333:project/my-project"},
	))
}

func TestResourcePatternsOverlap_DifferentRegions(t *testing.T) {
	assert.False(t, resourcePatternsOverlap(
		[]string{"arn:aws:codebuild:us-east-1:111122223333:project/foo"},
		[]string{"arn:aws:codebuild:eu-west-1:111122223333:project/foo"},
	))
}

func TestResourcePatternsOverlap_DifferentAccounts(t *testing.T) {
	assert.False(t, resourcePatternsOverlap(
		[]string{"arn:aws:codebuild:us-east-1:111122223333:project/foo"},
		[]string{"arn:aws:codebuild:us-east-1:999988887777:project/foo"},
	))
}

func TestResourcePatternsOverlap_EmptySlices(t *testing.T) {
	assert.False(t, resourcePatternsOverlap(nil, nil))
	assert.False(t, resourcePatternsOverlap([]string{"*"}, nil))
	assert.False(t, resourcePatternsOverlap(nil, []string{"*"}))
}

func TestResourcePatternsOverlap_MultiplePatternsAtLeastOneOverlaps(t *testing.T) {
	assert.True(t, resourcePatternsOverlap(
		[]string{
			"arn:aws:codebuild:eu-west-1:111122223333:project/*",
			"arn:aws:codebuild:us-east-1:111122223333:project/*",
		},
		[]string{"arn:aws:codebuild:us-east-1:111122223333:project/my-project"},
	))
}

// ---------------------------------------------------------------------------
// arnPatternsCompatible
// ---------------------------------------------------------------------------

func TestArnPatternsCompatible_Star(t *testing.T) {
	assert.True(t, arnPatternsCompatible("*", "anything"))
	assert.True(t, arnPatternsCompatible("anything", "*"))
	assert.True(t, arnPatternsCompatible("*", "*"))
}

func TestArnPatternsCompatible_SameFullARN(t *testing.T) {
	a := "arn:aws:codebuild:us-east-1:111122223333:project/foo"
	assert.True(t, arnPatternsCompatible(a, a))
}

func TestArnPatternsCompatible_DifferentService(t *testing.T) {
	a := "arn:aws:codebuild:us-east-1:111122223333:project/foo"
	b := "arn:aws:s3:us-east-1:111122223333:bucket/foo"
	assert.False(t, arnPatternsCompatible(a, b))
}

func TestArnPatternsCompatible_WildcardRegion(t *testing.T) {
	a := "arn:aws:codebuild:*:111122223333:project/foo"
	b := "arn:aws:codebuild:us-east-1:111122223333:project/foo"
	assert.True(t, arnPatternsCompatible(a, b))
}

func TestArnPatternsCompatible_TooFewParts(t *testing.T) {
	// If either ARN has fewer than 5 colon-separated parts, return true (permissive)
	assert.True(t, arnPatternsCompatible("short", "arn:aws:s3:::bucket"))
	assert.True(t, arnPatternsCompatible("arn:aws:s3:::bucket", "short"))
}

// ---------------------------------------------------------------------------
// synthesizeCreateThenUsePermissions
// ---------------------------------------------------------------------------

func TestSynthesizeCreateThenUsePermissions_NoPrincipalWithCreate(t *testing.T) {
	// No one has codebuild:CreateProject, so no synthetic edges
	results := []output.AWSIAMRelationship{
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:user/alice"}},
			Resource:  output.AWSResource{ARN: "arn:aws:s3:::my-bucket"},
			Action:    "s3:GetObject",
		},
	}
	state := buildMinimalState()
	out := synthesizeCreateThenUsePermissions(results, state)
	// Should return same results, no synthetic additions
	assert.Len(t, out, 1)
}

func TestSynthesizeCreateThenUsePermissions_HasCreateButAlreadyHasUse(t *testing.T) {
	// User has codebuild:CreateProject and already has codebuild:StartBuild, so no synthetic edge
	results := []output.AWSIAMRelationship{
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:role/build-role"}},
			Resource:  output.AWSResource{ARN: "codebuild.amazonaws.com"},
			Action:    "codebuild:CreateProject",
		},
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: "arn:aws:iam::111122223333:role/build-role"}},
			Resource:  output.AWSResource{ARN: "arn:aws:codebuild:us-east-1:111122223333:project/existing"},
			Action:    "codebuild:StartBuild",
		},
	}
	state := buildMinimalState()
	out := synthesizeCreateThenUsePermissions(results, state)
	assert.Len(t, out, 2, "No synthetic edges should be added when use already exists")
}

func TestSynthesizeCreateThenUsePermissions_AddsEdge(t *testing.T) {
	// Build a GAAD where a role has:
	// - codebuild:CreateProject on * (identity policy)
	// - codebuild:StartBuild on * (identity policy)
	// And results show codebuild:CreateProject allowed on codebuild.amazonaws.com
	// but NOT codebuild:StartBuild (no matching resource exists yet)
	createAction := types.DynaString{"codebuild:CreateProject", "codebuild:StartBuild", "codebuild:StartBuildBatch"}
	createResource := types.DynaString{"*"}
	createStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &createAction, Resource: &createResource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	roleArn := "arn:aws:iam::111122223333:role/build-role"
	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		roles: []types.RoleDetail{
			{
				Arn:      roleArn,
				RoleName: "build-role",
				AssumeRolePolicyDocument: types.Policy{
					Version:   "2012-10-17",
					Statement: &trustStmts,
				},
				RolePolicyList: []types.InlinePolicy{
					{
						PolicyName: "CodeBuildAccess",
						PolicyDocument: types.Policy{
							Version:   "2012-10-17",
							Statement: &createStmts,
						},
					},
				},
			},
		},
	})
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	// Existing results: only codebuild:CreateProject was matched
	results := []output.AWSIAMRelationship{
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: roleArn}},
			Resource:  output.AWSResource{ARN: "codebuild.amazonaws.com"},
			Action:    "codebuild:CreateProject",
		},
	}

	out := synthesizeCreateThenUsePermissions(results, state)

	// Should add synthetic edges for codebuild:StartBuild and codebuild:StartBuildBatch
	assert.Greater(t, len(out), 1, "Expected synthetic edges to be added")

	syntheticActions := map[string]bool{}
	for _, rel := range out[1:] {
		syntheticActions[rel.Action] = true
		assert.Equal(t, roleArn, rel.Principal.ARN)
	}
	assert.True(t, syntheticActions["codebuild:StartBuild"], "Expected codebuild:StartBuild synthetic edge")
	assert.True(t, syntheticActions["codebuild:StartBuildBatch"], "Expected codebuild:StartBuildBatch synthetic edge")
}

func TestSynthesizeCreateThenUsePermissions_NoUseStatement(t *testing.T) {
	// Role has codebuild:CreateProject but NOT codebuild:StartBuild in identity policies
	createAction := types.DynaString{"codebuild:CreateProject"}
	createResource := types.DynaString{"*"}
	createStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &createAction, Resource: &createResource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	roleArn := "arn:aws:iam::111122223333:role/limited-role"
	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		roles: []types.RoleDetail{
			{
				Arn:      roleArn,
				RoleName: "limited-role",
				AssumeRolePolicyDocument: types.Policy{
					Version:   "2012-10-17",
					Statement: &trustStmts,
				},
				RolePolicyList: []types.InlinePolicy{
					{
						PolicyName: "CreateOnly",
						PolicyDocument: types.Policy{
							Version:   "2012-10-17",
							Statement: &createStmts,
						},
					},
				},
			},
		},
	})
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	results := []output.AWSIAMRelationship{
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: roleArn}},
			Resource:  output.AWSResource{ARN: "codebuild.amazonaws.com"},
			Action:    "codebuild:CreateProject",
		},
	}

	out := synthesizeCreateThenUsePermissions(results, state)
	assert.Len(t, out, 1, "No synthetic edges when principal lacks use action in policies")
}

func TestSynthesizeCreateThenUsePermissions_NonOverlappingRegions(t *testing.T) {
	// Role has:
	// - codebuild:CreateProject on arn:aws:codebuild:us-east-1:111122223333:project/*
	// - codebuild:StartBuild on arn:aws:codebuild:eu-west-1:111122223333:project/*
	// The resource patterns don't overlap (different regions), so no synthetic edge.
	createAction := types.DynaString{"codebuild:CreateProject"}
	createResource := types.DynaString{"arn:aws:codebuild:us-east-1:111122223333:project/*"}
	createStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &createAction, Resource: &createResource},
	}

	useAction := types.DynaString{"codebuild:StartBuild"}
	useResource := types.DynaString{"arn:aws:codebuild:eu-west-1:111122223333:project/*"}
	useStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &useAction, Resource: &useResource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	roleArn := "arn:aws:iam::111122223333:role/region-split-role"
	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		roles: []types.RoleDetail{
			{
				Arn:      roleArn,
				RoleName: "region-split-role",
				AssumeRolePolicyDocument: types.Policy{
					Version:   "2012-10-17",
					Statement: &trustStmts,
				},
				RolePolicyList: []types.InlinePolicy{
					{
						PolicyName: "Create",
						PolicyDocument: types.Policy{
							Version:   "2012-10-17",
							Statement: &createStmts,
						},
					},
					{
						PolicyName: "Use",
						PolicyDocument: types.Policy{
							Version:   "2012-10-17",
							Statement: &useStmts,
						},
					},
				},
			},
		},
	})
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	results := []output.AWSIAMRelationship{
		{
			Principal: output.AWSIAMResource{AWSResource: output.AWSResource{ARN: roleArn}},
			Resource:  output.AWSResource{ARN: "codebuild.amazonaws.com"},
			Action:    "codebuild:CreateProject",
		},
	}

	out := synthesizeCreateThenUsePermissions(results, state)
	assert.Len(t, out, 1, "No synthetic edges when resource regions don't overlap")
}

// ---------------------------------------------------------------------------
// getStmtResources
// ---------------------------------------------------------------------------

func TestGetStmtResources_Role(t *testing.T) {
	action := types.DynaString{"codebuild:CreateProject"}
	resource := types.DynaString{"arn:aws:codebuild:us-east-1:111122223333:project/*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action, Resource: &resource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	roleArn := "arn:aws:iam::111122223333:role/test-role"
	gaad := newTestGAADFromOpts(newTestGAADOpts{
		roles: []types.RoleDetail{
			{
				Arn:      roleArn,
				RoleName: "test-role",
				AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts},
				RolePolicyList: []types.InlinePolicy{
					{
						PolicyName:     "CreateProject",
						PolicyDocument: types.Policy{Version: "2012-10-17", Statement: &stmts},
					},
				},
			},
		},
	})
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	resources := getStmtResources(roleArn, "codebuild:CreateProject", state)
	require.Len(t, resources, 1)
	assert.Equal(t, "arn:aws:codebuild:us-east-1:111122223333:project/*", resources[0])
}

func TestGetStmtResources_RoleManagedPolicy(t *testing.T) {
	action := types.DynaString{"codebuild:StartBuild"}
	resource := types.DynaString{"*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action, Resource: &resource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	policyArn := "arn:aws:iam::111122223333:policy/StartBuild"
	roleArn := "arn:aws:iam::111122223333:role/test-role"
	gaad := newTestGAADFromOpts(newTestGAADOpts{
		roles: []types.RoleDetail{
			{
				Arn:                      roleArn,
				RoleName:                 "test-role",
				AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts},
				AttachedManagedPolicies:  []types.ManagedPolicy{{PolicyName: "StartBuild", PolicyArn: policyArn}},
			},
		},
		policies: []types.ManagedPolicyDetail{
			{
				PolicyName: "StartBuild",
				Arn:        policyArn,
				PolicyVersionList: []types.PolicyVersion{
					{VersionId: "v1", IsDefaultVersion: true, Document: types.Policy{Version: "2012-10-17", Statement: &stmts}},
				},
			},
		},
	})
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	resources := getStmtResources(roleArn, "codebuild:StartBuild", state)
	require.Len(t, resources, 1)
	assert.Equal(t, "*", resources[0])
}

func TestGetStmtResources_User(t *testing.T) {
	action := types.DynaString{"codebuild:CreateProject"}
	resource := types.DynaString{"*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action, Resource: &resource},
	}

	userArn := "arn:aws:iam::111122223333:user/alice"
	gaad := newTestGAADFromOpts(newTestGAADOpts{
		users: []types.UserDetail{
			{
				Arn:      userArn,
				UserName: "alice",
				UserPolicyList: []types.InlinePolicy{
					{PolicyName: "CreateProject", PolicyDocument: types.Policy{Version: "2012-10-17", Statement: &stmts}},
				},
			},
		},
	})
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	resources := getStmtResources(userArn, "codebuild:CreateProject", state)
	require.Len(t, resources, 1)
	assert.Equal(t, "*", resources[0])
}

func TestGetStmtResources_UserGroupPolicy(t *testing.T) {
	action := types.DynaString{"codebuild:StartBuild"}
	resource := types.DynaString{"arn:aws:codebuild:*:111122223333:project/*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action, Resource: &resource},
	}

	userArn := "arn:aws:iam::111122223333:user/alice"
	gaad := newTestGAADFromOpts(newTestGAADOpts{
		users: []types.UserDetail{
			{
				Arn:       userArn,
				UserName:  "alice",
				GroupList: []string{"builders"},
			},
		},
		groups: []types.GroupDetail{
			{
				Arn:       "arn:aws:iam::111122223333:group/builders",
				GroupName: "builders",
				GroupPolicyList: []types.InlinePolicy{
					{PolicyName: "StartBuild", PolicyDocument: types.Policy{Version: "2012-10-17", Statement: &stmts}},
				},
			},
		},
	})
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	resources := getStmtResources(userArn, "codebuild:StartBuild", state)
	require.Len(t, resources, 1)
	assert.Equal(t, "arn:aws:codebuild:*:111122223333:project/*", resources[0])
}

func TestGetStmtResources_NilResource(t *testing.T) {
	// If a statement has Action but no Resource field, it implies "*"
	action := types.DynaString{"codebuild:CreateProject"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	roleArn := "arn:aws:iam::111122223333:role/test"
	gaad := newTestGAADFromOpts(newTestGAADOpts{
		roles: []types.RoleDetail{
			{
				Arn:                      roleArn,
				RoleName:                 "test",
				AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts},
				RolePolicyList: []types.InlinePolicy{
					{PolicyName: "P", PolicyDocument: types.Policy{Version: "2012-10-17", Statement: &stmts}},
				},
			},
		},
	})
	state := NewAnalyzerMemoryState(gaad, orgpolicies.NewDefaultOrgPolicies(), nil)

	resources := getStmtResources(roleArn, "codebuild:CreateProject", state)
	require.Len(t, resources, 1)
	assert.Equal(t, "*", resources[0])
}

func TestGetStmtResources_UnknownPrincipal(t *testing.T) {
	state := buildMinimalState()
	resources := getStmtResources("arn:aws:iam::111122223333:user/unknown", "codebuild:CreateProject", state)
	assert.Nil(t, resources)
}
