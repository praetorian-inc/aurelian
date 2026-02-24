package gaad

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/cache"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// collectRelationships returns all values from a relationship map as a slice (test helper).
func collectRelationships(m cache.Map[output.AWSIAMRelationship]) []output.AWSIAMRelationship {
	var out []output.AWSIAMRelationship
	m.Range(func(_ string, rel output.AWSIAMRelationship) bool {
		out = append(out, rel)
		return true
	})
	return out
}

// newTestGAADOpts holds optional fields for building test GAAD data.
type newTestGAADOpts struct {
	accountID string
	users     []types.UserDetail
	groups    []types.GroupDetail
	roles     []types.RoleDetail
	policies  []types.ManagedPolicyDetail
}

func newTestGAADFromOpts(o newTestGAADOpts) *types.AuthorizationAccountDetails {
	return types.NewAuthorizationAccountDetails(o.accountID, o.users, o.groups, o.roles, o.policies)
}

// ---------------------------------------------------------------------------
// NewGaadAnalyzer
// ---------------------------------------------------------------------------

func TestNewGaadAnalyzer(t *testing.T) {
	ga := NewGaadAnalyzer()
	require.NotNil(t, ga)
}

// ---------------------------------------------------------------------------
// Analyze — end-to-end
// ---------------------------------------------------------------------------

func TestAnalyze_EmptyGAAD(t *testing.T) {
	ga := NewGaadAnalyzer()
	gaad := types.NewAuthorizationAccountDetails("", nil, nil, nil, nil)
	orgPol := orgpolicies.NewDefaultOrgPolicies()

	results, err := ga.Analyze(gaad, orgPol, cache.Map[output.AWSResource]{})
	require.NoError(t, err)
	assert.Equal(t, 0, results.Len())
}

func TestAnalyze_UserWithPassRolePermission(t *testing.T) {
	// Setup: user "alice" has an inline policy granting iam:PassRole on all roles
	// plus a role "target-role" that is the target resource.
	// Expected: the analyzer finds alice -> iam:PassRole -> target-role

	passRoleAction := types.DynaString{"iam:PassRole"}
	passRoleResource := types.DynaString{"*"}
	passRoleStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &passRoleAction, Resource: &passRoleResource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:user/alice"}
	trustStmts := types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   &trustAction,
			Resource: &trustResource,
			Principal: &types.Principal{
				AWS: &trustPrincipal,
			},
		},
	}

	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		users: []types.UserDetail{
			{
				Arn:      "arn:aws:iam::111122223333:user/alice",
				UserName: "alice",
				UserId:   "AIDA111",
				Path:     "/",
				UserPolicyList: []types.InlinePolicy{
					{
						PolicyName: "PassRole",
						PolicyDocument: types.Policy{
							Version:   "2012-10-17",
							Statement: &passRoleStmts,
						},
					},
				},
			},
		},
		roles: []types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111122223333:role/target-role",
				RoleName: "target-role",
				RoleId:   "AROA111",
				Path:     "/",
				AssumeRolePolicyDocument: types.Policy{
					Version:   "2012-10-17",
					Statement: &trustStmts,
				},
			},
		},
	})

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()

	results, err := ga.Analyze(gaad, orgPol, cache.Map[output.AWSResource]{})
	require.NoError(t, err)

	// Find PassRole result
	foundPassRole := false
	for _, rel := range collectRelationships(results) {
		if rel.Action == "iam:PassRole" &&
			rel.Principal.ARN == "arn:aws:iam::111122223333:user/alice" &&
			rel.Resource.ARN == "arn:aws:iam::111122223333:role/target-role" {
			foundPassRole = true
		}
	}
	assert.True(t, foundPassRole, "Expected to find iam:PassRole edge from alice to target-role")
}

func TestAnalyze_RoleWithManagedPolicy(t *testing.T) {
	// Role with an attached managed policy granting iam:PassRole
	passRoleAction := types.DynaString{"iam:PassRole"}
	passRoleResource := types.DynaString{"*"}
	passRoleStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &passRoleAction, Resource: &passRoleResource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	policyArn := "arn:aws:iam::111122223333:policy/PassRolePolicy"
	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		roles: []types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111122223333:role/source-role",
				RoleName: "source-role",
				RoleId:   "AROA222",
				Path:     "/",
				AssumeRolePolicyDocument: types.Policy{
					Version:   "2012-10-17",
					Statement: &trustStmts,
				},
				AttachedManagedPolicies: []types.ManagedPolicy{
					{PolicyName: "PassRolePolicy", PolicyArn: policyArn},
				},
			},
			{
				Arn:      "arn:aws:iam::111122223333:role/target-role",
				RoleName: "target-role",
				RoleId:   "AROA333",
				Path:     "/",
				AssumeRolePolicyDocument: types.Policy{
					Version:   "2012-10-17",
					Statement: &trustStmts,
				},
			},
		},
		policies: []types.ManagedPolicyDetail{
			{
				PolicyName: "PassRolePolicy",
				Arn:        policyArn,
				PolicyVersionList: []types.PolicyVersion{
					{
						VersionId:        "v1",
						IsDefaultVersion: true,
						Document: types.Policy{
							Version:   "2012-10-17",
							Statement: &passRoleStmts,
						},
					},
				},
			},
		},
	})

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()

	results, err := ga.Analyze(gaad, orgPol, cache.Map[output.AWSResource]{})
	require.NoError(t, err)

	foundPassRole := false
	for _, rel := range collectRelationships(results) {
		if rel.Action == "iam:PassRole" &&
			rel.Principal.ARN == "arn:aws:iam::111122223333:role/source-role" {
			foundPassRole = true
			break
		}
	}
	assert.True(t, foundPassRole, "Expected source-role to have iam:PassRole via managed policy")
}

func TestAnalyze_UserWithGroupPolicy(t *testing.T) {
	// User "bob" is in group "admins" which has a policy granting iam:CreateAccessKey
	createKeyAction := types.DynaString{"iam:CreateAccessKey"}
	createKeyResource := types.DynaString{"*"}
	createKeyStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &createKeyAction, Resource: &createKeyResource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		users: []types.UserDetail{
			{
				Arn:       "arn:aws:iam::111122223333:user/bob",
				UserName:  "bob",
				UserId:    "AIDA222",
				Path:      "/",
				GroupList: []string{"admins"},
			},
		},
		groups: []types.GroupDetail{
			{
				Arn:       "arn:aws:iam::111122223333:group/admins",
				GroupName: "admins",
				GroupId:   "AGPA111",
				Path:      "/",
				GroupPolicyList: []types.InlinePolicy{
					{
						PolicyName: "AdminKeys",
						PolicyDocument: types.Policy{
							Version:   "2012-10-17",
							Statement: &createKeyStmts,
						},
					},
				},
			},
		},
		roles: []types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111122223333:role/some-role",
				RoleName: "some-role",
				RoleId:   "AROA444",
				Path:     "/",
				AssumeRolePolicyDocument: types.Policy{
					Version:   "2012-10-17",
					Statement: &trustStmts,
				},
			},
		},
	})

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()

	results, err := ga.Analyze(gaad, orgPol, cache.Map[output.AWSResource]{})
	require.NoError(t, err)

	foundCreateKey := false
	for _, rel := range collectRelationships(results) {
		if rel.Action == "iam:CreateAccessKey" &&
			rel.Principal.ARN == "arn:aws:iam::111122223333:user/bob" {
			foundCreateKey = true
			break
		}
	}
	assert.True(t, foundCreateKey, "Expected bob to have iam:CreateAccessKey via group policy")
}

func TestAnalyze_AssumeRoleTrustPolicy(t *testing.T) {
	// Role trust policy allows a service principal (lambda.amazonaws.com) to assume it
	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustService := types.DynaString{"lambda.amazonaws.com"}
	trustStmts := types.PolicyStatementList{
		{
			Effect:    "Allow",
			Action:    &trustAction,
			Resource:  &trustResource,
			Principal: &types.Principal{Service: &trustService},
		},
	}

	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		roles: []types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111122223333:role/lambda-exec-role",
				RoleName: "lambda-exec-role",
				RoleId:   "AROA555",
				Path:     "/",
				AssumeRolePolicyDocument: types.Policy{
					Version:   "2012-10-17",
					Statement: &trustStmts,
				},
			},
		},
	})

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()

	results, err := ga.Analyze(gaad, orgPol, cache.Map[output.AWSResource]{})
	require.NoError(t, err)

	foundAssumeRole := false
	for _, rel := range collectRelationships(results) {
		if rel.Action == "sts:AssumeRole" &&
			rel.Resource.ARN == "arn:aws:iam::111122223333:role/lambda-exec-role" {
			foundAssumeRole = true
			break
		}
	}
	assert.True(t, foundAssumeRole, "Expected lambda.amazonaws.com to be able to assume the role")
}

func TestAnalyze_ResourcePolicy(t *testing.T) {
	// A resource with a resource policy granting lambda:InvokeFunction to lambda.amazonaws.com
	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	lambdaAction := types.DynaString{"lambda:InvokeFunction"}
	lambdaResource := types.DynaString{"arn:aws:lambda:us-east-1:111122223333:function:my-func"}
	lambdaService := types.DynaString{"s3.amazonaws.com"}
	lambdaStmts := types.PolicyStatementList{
		{
			Effect:    "Allow",
			Action:    &lambdaAction,
			Resource:  &lambdaResource,
			Principal: &types.Principal{Service: &lambdaService},
		},
	}

	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		roles: []types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111122223333:role/dummy",
				RoleName: "dummy",
				AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts},
			},
		},
	})

	resources := []output.AWSResource{
		{
			ResourceType: "AWS::Lambda::Function",
			ResourceID:   "my-func",
			ARN:          "arn:aws:lambda:us-east-1:111122223333:function:my-func",
			AccountRef:   "111122223333",
			Region:       "us-east-1",
			ResourcePolicy: &types.Policy{
				Version:   "2012-10-17",
				Statement: &lambdaStmts,
			},
		},
	}

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()

	results, err := ga.Analyze(gaad, orgPol, newResourceMap(resources))
	require.NoError(t, err)

	foundInvoke := false
	for _, rel := range collectRelationships(results) {
		if rel.Action == "lambda:InvokeFunction" &&
			rel.Resource.ARN == "arn:aws:lambda:us-east-1:111122223333:function:my-func" {
			foundInvoke = true
			break
		}
	}
	assert.True(t, foundInvoke, "Expected s3.amazonaws.com to be able to invoke the lambda via resource policy")
}

func TestAnalyze_UserWithPermissionsBoundary(t *testing.T) {
	// User has iam:* but a boundary restricts to only iam:PassRole
	allIAMAction := types.DynaString{"iam:*"}
	allResource := types.DynaString{"*"}
	identityStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &allIAMAction, Resource: &allResource},
	}

	boundaryAction := types.DynaString{"iam:PassRole"}
	boundaryStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &boundaryAction, Resource: &allResource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &allResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	boundaryArn := "arn:aws:iam::111122223333:policy/PassRoleBoundary"
	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		users: []types.UserDetail{
			{
				Arn:      "arn:aws:iam::111122223333:user/bounded-user",
				UserName: "bounded-user",
				UserId:   "AIDA333",
				UserPolicyList: []types.InlinePolicy{
					{PolicyName: "AllIAM", PolicyDocument: types.Policy{Version: "2012-10-17", Statement: &identityStmts}},
				},
				PermissionsBoundary: types.ManagedPolicy{
					PolicyName: "PassRoleBoundary",
					PolicyArn:  boundaryArn,
				},
			},
		},
		roles: []types.RoleDetail{
			{
				Arn:                      "arn:aws:iam::111122223333:role/target-role",
				RoleName:                 "target-role",
				RoleId:                   "AROA666",
				AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts},
			},
		},
		policies: []types.ManagedPolicyDetail{
			{
				PolicyName: "PassRoleBoundary",
				Arn:        boundaryArn,
				PolicyVersionList: []types.PolicyVersion{
					{VersionId: "v1", IsDefaultVersion: true, Document: types.Policy{Version: "2012-10-17", Statement: &boundaryStmts}},
				},
			},
		},
	})

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()
	results, err := ga.Analyze(gaad, orgPol, cache.Map[output.AWSResource]{})
	require.NoError(t, err)

	// The boundary restricts to iam:PassRole only, so CreateAccessKey etc should NOT appear
	for _, rel := range collectRelationships(results) {
		if rel.Principal.ARN == "arn:aws:iam::111122223333:user/bounded-user" {
			if rel.Action == "iam:CreateAccessKey" || rel.Action == "iam:CreateUser" || rel.Action == "iam:AttachUserPolicy" {
				t.Errorf("Expected boundary to restrict %s, but it was allowed", rel.Action)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// buildPolicyData
// ---------------------------------------------------------------------------

func TestBuildPolicyData(t *testing.T) {
	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	gaad := newTestGAADFromOpts(newTestGAADOpts{
		roles: []types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111122223333:role/test",
				RoleName: "test",
				AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts},
			},
		},
	})

	lambdaAction := types.DynaString{"lambda:InvokeFunction"}
	lambdaResource := types.DynaString{"*"}
	lambdaService := types.DynaString{"s3.amazonaws.com"}
	lambdaStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &lambdaAction, Resource: &lambdaResource, Principal: &types.Principal{Service: &lambdaService}},
	}

	resources := []output.AWSResource{
		{
			ARN: "arn:aws:lambda:us-east-1:111122223333:function:my-func",
			ResourcePolicy: &types.Policy{
				Version:   "2012-10-17",
				Statement: &lambdaStmts,
			},
		},
		{
			ARN: "arn:aws:s3:::no-policy-bucket",
			// No resource policy
		},
	}

	orgPol := orgpolicies.NewDefaultOrgPolicies()
	pd := buildPolicyData(gaad, orgPol, newResourceMap(resources))
	require.NotNil(t, pd)
}

// ---------------------------------------------------------------------------
// buildPrincipal
// ---------------------------------------------------------------------------

func TestBuildPrincipal_Found(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), cache.Map[output.AWSResource]{})

	principal := buildPrincipal("arn:aws:iam::111122223333:user/alice", state)
	assert.Equal(t, "arn:aws:iam::111122223333:user/alice", principal.ARN)
	assert.Equal(t, "AWS::IAM::User", principal.ResourceType)
}

func TestBuildPrincipal_NotFound(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), cache.Map[output.AWSResource]{})

	principal := buildPrincipal("arn:aws:iam::999988887777:user/unknown", state)
	assert.Equal(t, "arn:aws:iam::999988887777:user/unknown", principal.ARN)
	assert.Equal(t, "arn:aws:iam::999988887777:user/unknown", principal.ResourceID)
	assert.Equal(t, "", principal.ResourceType)
}

// ---------------------------------------------------------------------------
// generateSyntheticPermissions (via Analyze)
// ---------------------------------------------------------------------------

func TestAnalyze_CreateThenUseSynthetic(t *testing.T) {
	// Build a scenario where a role can create and use CodeBuild projects
	// The create action is found by the evaluator (matched against codebuild service resource)
	// But the use action has no matching existing resource - so it must be synthesized

	allCodeBuildAction := types.DynaString{"codebuild:CreateProject", "codebuild:StartBuild", "codebuild:StartBuildBatch"}
	allResource := types.DynaString{"*"}
	cbStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &allCodeBuildAction, Resource: &allResource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &allResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		roles: []types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111122223333:role/cb-role",
				RoleName: "cb-role",
				RoleId:   "AROA777",
				AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts},
				RolePolicyList: []types.InlinePolicy{
					{PolicyName: "CB", PolicyDocument: types.Policy{Version: "2012-10-17", Statement: &cbStmts}},
				},
			},
		},
	})

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()
	results, err := ga.Analyze(gaad, orgPol, cache.Map[output.AWSResource]{})
	require.NoError(t, err)

	// Check for synthetic edges
	hasCreate := false
	hasStartBuild := false
	hasStartBuildBatch := false
	for _, rel := range collectRelationships(results) {
		if rel.Principal.ARN == "arn:aws:iam::111122223333:role/cb-role" {
			switch rel.Action {
			case "codebuild:CreateProject":
				hasCreate = true
			case "codebuild:StartBuild":
				hasStartBuild = true
			case "codebuild:StartBuildBatch":
				hasStartBuildBatch = true
			}
		}
	}
	assert.True(t, hasCreate, "Expected codebuild:CreateProject to be found")
	assert.True(t, hasStartBuild, "Expected synthetic codebuild:StartBuild edge")
	assert.True(t, hasStartBuildBatch, "Expected synthetic codebuild:StartBuildBatch edge")
}

func TestAnalyze_AssumeRoleDenyStatementInTrustPolicy(t *testing.T) {
	// Trust policy with a Deny statement should not produce an AssumeRole edge
	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipalAlice := types.DynaString{"arn:aws:iam::111122223333:user/alice"}
	trustStmts := types.PolicyStatementList{
		{
			Effect:    "Deny",
			Action:    &trustAction,
			Resource:  &trustResource,
			Principal: &types.Principal{AWS: &trustPrincipalAlice},
		},
	}

	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		users: []types.UserDetail{
			{Arn: "arn:aws:iam::111122223333:user/alice", UserName: "alice", UserId: "AIDA444"},
		},
		roles: []types.RoleDetail{
			{
				Arn:                      "arn:aws:iam::111122223333:role/deny-role",
				RoleName:                 "deny-role",
				RoleId:                   "AROA888",
				AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts},
			},
		},
	})

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()
	results, err := ga.Analyze(gaad, orgPol, cache.Map[output.AWSResource]{})
	require.NoError(t, err)

	for _, rel := range collectRelationships(results) {
		if rel.Action == "sts:AssumeRole" &&
			rel.Principal.ARN == "arn:aws:iam::111122223333:user/alice" &&
			rel.Resource.ARN == "arn:aws:iam::111122223333:role/deny-role" {
			t.Error("Should not have produced AssumeRole edge due to Deny in trust policy")
		}
	}
}

func TestAnalyze_TrustPolicyNilPrincipal(t *testing.T) {
	// Trust policy with nil principal should be skipped gracefully
	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &trustResource, Principal: nil},
	}

	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		roles: []types.RoleDetail{
			{
				Arn:                      "arn:aws:iam::111122223333:role/nil-principal-role",
				RoleName:                 "nil-principal-role",
				RoleId:                   "AROA999",
				AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts},
			},
		},
	})

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()
	results, err := ga.Analyze(gaad, orgPol, cache.Map[output.AWSResource]{})
	require.NoError(t, err)
	// Should not panic, might or might not produce results depending on evaluator
	_ = results
}

func TestAnalyze_ResourcePolicyNoPrivEscActions(t *testing.T) {
	// Resource policy with a non-priv-esc action should not produce edges
	s3Action := types.DynaString{"s3:GetObject"}
	s3Resource := types.DynaString{"arn:aws:s3:::my-bucket/*"}
	s3Service := types.DynaString{"lambda.amazonaws.com"}
	s3Stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &s3Action, Resource: &s3Resource, Principal: &types.Principal{Service: &s3Service}},
	}

	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
	})

	resources := []output.AWSResource{
		{
			ResourceType: "AWS::S3::Bucket",
			ARN:          "arn:aws:s3:::my-bucket",
			AccountRef:   "111122223333",
			ResourcePolicy: &types.Policy{
				Version:   "2012-10-17",
				Statement: &s3Stmts,
			},
		},
	}

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()
	results, err := ga.Analyze(gaad, orgPol, newResourceMap(resources))
	require.NoError(t, err)

	for _, rel := range collectRelationships(results) {
		if rel.Action == "s3:GetObject" {
			t.Error("s3:GetObject is not a priv-esc action; should not appear in results")
		}
	}
}

func TestAnalyze_ResourcePolicyNilStatements(t *testing.T) {
	// Resource with nil resource policy or nil statements should be handled gracefully
	gaad := types.NewAuthorizationAccountDetails("111122223333", nil, nil, nil, nil)

	resources := []output.AWSResource{
		{
			ResourceType:   "AWS::Lambda::Function",
			ARN:            "arn:aws:lambda:us-east-1:111122223333:function:null-policy",
			AccountRef:     "111122223333",
			ResourcePolicy: nil,
		},
		{
			ResourceType: "AWS::Lambda::Function",
			ARN:          "arn:aws:lambda:us-east-1:111122223333:function:empty-stmts",
			AccountRef:   "111122223333",
			ResourcePolicy: &types.Policy{
				Version:   "2012-10-17",
				Statement: nil,
			},
		},
	}

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()
	results, err := ga.Analyze(gaad, orgPol, newResourceMap(resources))
	require.NoError(t, err)
	// Should not panic
	_ = results
}

func TestAnalyze_MultipleUsersAndRoles(t *testing.T) {
	// Test with multiple users and roles to ensure concurrent processing works
	passRoleAction := types.DynaString{"iam:PassRole"}
	allResource := types.DynaString{"*"}
	passRoleStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &passRoleAction, Resource: &allResource},
	}

	createKeyAction := types.DynaString{"iam:CreateAccessKey"}
	createKeyStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &createKeyAction, Resource: &allResource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustPrincipal := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &trustAction, Resource: &allResource, Principal: &types.Principal{AWS: &trustPrincipal}},
	}

	gaad := newTestGAADFromOpts(newTestGAADOpts{
		accountID: "111122223333",
		users: []types.UserDetail{
			{
				Arn:      "arn:aws:iam::111122223333:user/alice",
				UserName: "alice",
				UserPolicyList: []types.InlinePolicy{
					{PolicyName: "PassRole", PolicyDocument: types.Policy{Version: "2012-10-17", Statement: &passRoleStmts}},
				},
			},
			{
				Arn:      "arn:aws:iam::111122223333:user/bob",
				UserName: "bob",
				UserPolicyList: []types.InlinePolicy{
					{PolicyName: "CreateKey", PolicyDocument: types.Policy{Version: "2012-10-17", Statement: &createKeyStmts}},
				},
			},
		},
		roles: []types.RoleDetail{
			{Arn: "arn:aws:iam::111122223333:role/r1", RoleName: "r1", AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts}},
			{Arn: "arn:aws:iam::111122223333:role/r2", RoleName: "r2", AssumeRolePolicyDocument: types.Policy{Version: "2012-10-17", Statement: &trustStmts}},
		},
	})

	ga := NewGaadAnalyzer()
	orgPol := orgpolicies.NewDefaultOrgPolicies()
	results, err := ga.Analyze(gaad, orgPol, cache.Map[output.AWSResource]{})
	require.NoError(t, err)

	assert.Greater(t, results.Len(), 0, "Expected at least some results from concurrent processing")
}
