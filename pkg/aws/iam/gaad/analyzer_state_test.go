package gaad

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testGAAD builds a small but complete AuthorizationAccountDetails for testing.
func testGAAD() *types.AuthorizationAccountDetails {
	passRoleAction := types.DynaString{"iam:PassRole"}
	passRoleResource := types.DynaString{"arn:aws:iam::111122223333:role/*"}
	passRoleStmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &passRoleAction, Resource: &passRoleResource},
	}

	trustAction := types.DynaString{"sts:AssumeRole"}
	trustResource := types.DynaString{"*"}
	trustPrincipalAWS := types.DynaString{"arn:aws:iam::111122223333:root"}
	trustStmts := types.PolicyStatementList{
		{
			Effect:   "Allow",
			Action:   &trustAction,
			Resource: &trustResource,
			Principal: &types.Principal{
				AWS: &trustPrincipalAWS,
			},
		},
	}

	s3Action := types.DynaString{"s3:GetObject"}
	s3Resource := types.DynaString{"*"}
	s3Stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &s3Action, Resource: &s3Resource},
	}

	return &types.AuthorizationAccountDetails{
		AccountID: "111122223333",
		UserDetailList: []types.UserDetail{
			{
				Arn:      "arn:aws:iam::111122223333:user/alice",
				UserName: "alice",
				UserId:   "AIDA1234567890",
				Path:     "/",
				GroupList: []string{"developers"},
				UserPolicyList: []types.InlinePolicy{
					{
						PolicyName: "UserInline",
						PolicyDocument: types.Policy{
							Version:   "2012-10-17",
							Statement: &s3Stmts,
						},
					},
				},
				AttachedManagedPolicies: []types.ManagedPolicy{
					{PolicyName: "PassRolePolicy", PolicyArn: "arn:aws:iam::111122223333:policy/PassRolePolicy"},
				},
			},
		},
		RoleDetailList: []types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111122223333:role/test-role",
				RoleName: "test-role",
				RoleId:   "AROA1234567890",
				Path:     "/",
				AssumeRolePolicyDocument: types.Policy{
					Version:   "2012-10-17",
					Statement: &trustStmts,
				},
				AttachedManagedPolicies: []types.ManagedPolicy{
					{PolicyName: "PassRolePolicy", PolicyArn: "arn:aws:iam::111122223333:policy/PassRolePolicy"},
				},
			},
		},
		GroupDetailList: []types.GroupDetail{
			{
				Arn:       "arn:aws:iam::111122223333:group/developers",
				GroupName: "developers",
				GroupId:   "AGPA1234567890",
				Path:      "/",
			},
		},
		Policies: []types.ManagedPolicyDetail{
			{
				PolicyName: "PassRolePolicy",
				Arn:        "arn:aws:iam::111122223333:policy/PassRolePolicy",
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
	}
}

// ---------------------------------------------------------------------------
// NewAnalyzerMemoryState
// ---------------------------------------------------------------------------

func TestNewAnalyzerMemoryState(t *testing.T) {
	gaad := testGAAD()
	orgPol := orgpolicies.NewDefaultOrgPolicies()
	resources := []output.AWSResource{
		{
			ResourceType: "AWS::S3::Bucket",
			ResourceID:   "my-bucket",
			ARN:          "arn:aws:s3:::my-bucket",
			AccountRef:   "111122223333",
			Region:       "us-east-1",
		},
	}

	state := NewAnalyzerMemoryState(gaad, orgPol, resources)
	require.NotNil(t, state)
	assert.Equal(t, gaad, state.Gaad)
	assert.Equal(t, orgPol, state.OrgPolicies)
	assert.Equal(t, resources, state.Resources)
}

// ---------------------------------------------------------------------------
// GetPolicyByArn
// ---------------------------------------------------------------------------

func TestGetPolicyByArn_Found(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	policy := state.GetPolicyByArn("arn:aws:iam::111122223333:policy/PassRolePolicy")
	require.NotNil(t, policy)
	assert.Equal(t, "PassRolePolicy", policy.PolicyName)
}

func TestGetPolicyByArn_NotFound(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	policy := state.GetPolicyByArn("arn:aws:iam::111122223333:policy/DoesNotExist")
	assert.Nil(t, policy)
}

// ---------------------------------------------------------------------------
// GetRole
// ---------------------------------------------------------------------------

func TestGetRole_Found(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	role := state.GetRole("arn:aws:iam::111122223333:role/test-role")
	require.NotNil(t, role)
	assert.Equal(t, "test-role", role.RoleName)
}

func TestGetRole_NotFound(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	role := state.GetRole("arn:aws:iam::111122223333:role/nonexistent")
	assert.Nil(t, role)
}

// ---------------------------------------------------------------------------
// GetUser
// ---------------------------------------------------------------------------

func TestGetUser_Found(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	user := state.GetUser("arn:aws:iam::111122223333:user/alice")
	require.NotNil(t, user)
	assert.Equal(t, "alice", user.UserName)
}

func TestGetUser_NotFound(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	user := state.GetUser("arn:aws:iam::111122223333:user/nonexistent")
	assert.Nil(t, user)
}

// ---------------------------------------------------------------------------
// GetGroupByName
// ---------------------------------------------------------------------------

func TestGetGroupByName_Found(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	group := state.GetGroupByName("developers")
	require.NotNil(t, group)
	assert.Equal(t, "developers", group.GroupName)
}

func TestGetGroupByName_NotFound(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	group := state.GetGroupByName("nonexistent-group")
	assert.Nil(t, group)
}

// ---------------------------------------------------------------------------
// GetResource
// ---------------------------------------------------------------------------

func TestGetResource_CloudResource(t *testing.T) {
	resources := []output.AWSResource{
		{
			ResourceType: "AWS::S3::Bucket",
			ResourceID:   "my-bucket",
			ARN:          "arn:aws:s3:::my-bucket",
			AccountRef:   "111122223333",
		},
	}
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), resources)

	r := state.GetResource("arn:aws:s3:::my-bucket")
	require.NotNil(t, r)
	assert.Equal(t, "AWS::S3::Bucket", r.ResourceType)
}

func TestGetResource_IAMRole(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)

	// IAM entities from GAAD are added to the resource cache
	r := state.GetResource("arn:aws:iam::111122223333:role/test-role")
	require.NotNil(t, r)
	assert.Equal(t, "AWS::IAM::Role", r.ResourceType)
}

func TestGetResource_IAMUser(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	r := state.GetResource("arn:aws:iam::111122223333:user/alice")
	require.NotNil(t, r)
	assert.Equal(t, "AWS::IAM::User", r.ResourceType)
}

func TestGetResource_IAMGroup(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	r := state.GetResource("arn:aws:iam::111122223333:group/developers")
	require.NotNil(t, r)
	assert.Equal(t, "AWS::IAM::Group", r.ResourceType)
}

func TestGetResource_IAMPolicy(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	r := state.GetResource("arn:aws:iam::111122223333:policy/PassRolePolicy")
	require.NotNil(t, r)
	assert.Equal(t, "AWS::IAM::ManagedPolicy", r.ResourceType)
}

func TestGetResource_Attacker(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	r := state.GetResource("attacker")
	require.NotNil(t, r)
	assert.Equal(t, "AWS::API::Gateway", r.ResourceType)
	assert.Equal(t, "attacker", r.ARN)
}

func TestGetResource_Service(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)

	// Services are added by addServicesToResourceCache
	r := state.GetResource("s3.amazonaws.com")
	require.NotNil(t, r)
	assert.Equal(t, "AWS::Service", r.ResourceType)
	assert.Equal(t, "s3", r.DisplayName)
}

func TestGetResource_NotFound(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)
	r := state.GetResource("arn:aws:s3:::nonexistent-bucket")
	assert.Nil(t, r)
}

func TestGetResource_FallbackToResourceID(t *testing.T) {
	resources := []output.AWSResource{
		{
			ResourceType: "AWS::Custom::Thing",
			ResourceID:   "custom-resource-id",
			ARN:          "",
			AccountRef:   "111122223333",
		},
	}
	state := NewAnalyzerMemoryState(
		&types.AuthorizationAccountDetails{},
		orgpolicies.NewDefaultOrgPolicies(),
		resources,
	)

	r := state.GetResource("custom-resource-id")
	require.NotNil(t, r)
	assert.Equal(t, "AWS::Custom::Thing", r.ResourceType)
}

// ---------------------------------------------------------------------------
// GetResourceDetails
// ---------------------------------------------------------------------------

func TestGetResourceDetails_Found(t *testing.T) {
	resources := []output.AWSResource{
		{
			ResourceType: "AWS::S3::Bucket",
			ResourceID:   "my-bucket",
			ARN:          "arn:aws:s3:::my-bucket",
			AccountRef:   "111122223333",
			Properties: map[string]any{
				"Tags": []any{
					map[string]any{"Key": "env", "Value": "prod"},
				},
			},
		},
	}
	state := NewAnalyzerMemoryState(&types.AuthorizationAccountDetails{}, orgpolicies.NewDefaultOrgPolicies(), resources)

	accountID, tags := state.GetResourceDetails("arn:aws:s3:::my-bucket")
	assert.Equal(t, "111122223333", accountID)
	assert.Equal(t, "prod", tags["env"])
}

func TestGetResourceDetails_NotFoundFallsBackToARNParsing(t *testing.T) {
	state := NewAnalyzerMemoryState(&types.AuthorizationAccountDetails{}, orgpolicies.NewDefaultOrgPolicies(), nil)

	accountID, tags := state.GetResourceDetails("arn:aws:iam::999988887777:role/some-role")
	assert.Equal(t, "999988887777", accountID)
	assert.Nil(t, tags)
}

func TestGetResourceDetails_InvalidARN(t *testing.T) {
	state := NewAnalyzerMemoryState(&types.AuthorizationAccountDetails{}, orgpolicies.NewDefaultOrgPolicies(), nil)

	accountID, tags := state.GetResourceDetails("not-an-arn")
	assert.Equal(t, "", accountID)
	assert.Nil(t, tags)
}

func TestGetResourceDetails_ServiceARN(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)

	// Services like "lambda.amazonaws.com" are stored by both the service name and the generated ARN
	accountID, tags := state.GetResourceDetails("lambda.amazonaws.com")
	assert.Equal(t, "*", accountID)
	assert.Empty(t, tags)
}

// ---------------------------------------------------------------------------
// GetResourcesByAction
// ---------------------------------------------------------------------------

func TestGetResourcesByAction_IAMPassRole(t *testing.T) {
	state := NewAnalyzerMemoryState(testGAAD(), orgpolicies.NewDefaultOrgPolicies(), nil)

	// iam:PassRole should match IAM role resources
	resources := state.GetResourcesByAction("iam:PassRole")
	// Should find at least the test-role (IAM roles are in the resource cache)
	found := false
	for _, r := range resources {
		if r.ARN == "arn:aws:iam::111122223333:role/test-role" {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected to find test-role in resources for iam:PassRole action")
}

// ---------------------------------------------------------------------------
// ExtractActions
// ---------------------------------------------------------------------------

func TestExtractActions_SpecificAction(t *testing.T) {
	action := types.DynaString{"iam:PassRole"}
	resource := types.DynaString{"*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action, Resource: &resource},
	}

	state := NewAnalyzerMemoryState(&types.AuthorizationAccountDetails{}, orgpolicies.NewDefaultOrgPolicies(), nil)
	actions := state.ExtractActions(&stmts)
	require.Len(t, actions, 1)
	assert.Equal(t, "iam:PassRole", actions[0])
}

func TestExtractActions_MultipleStatements(t *testing.T) {
	action1 := types.DynaString{"iam:PassRole"}
	action2 := types.DynaString{"s3:GetObject", "s3:PutObject"}
	resource := types.DynaString{"*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action1, Resource: &resource},
		{Effect: "Allow", Action: &action2, Resource: &resource},
	}

	state := NewAnalyzerMemoryState(&types.AuthorizationAccountDetails{}, orgpolicies.NewDefaultOrgPolicies(), nil)
	actions := state.ExtractActions(&stmts)
	require.Len(t, actions, 3)
	assert.Contains(t, actions, "iam:PassRole")
	assert.Contains(t, actions, "s3:GetObject")
	assert.Contains(t, actions, "s3:PutObject")
}

func TestExtractActions_NilActionField(t *testing.T) {
	// Statement with no Action field (e.g., NotAction-only)
	resource := types.DynaString{"*"}
	notAction := types.DynaString{"iam:*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", NotAction: &notAction, Resource: &resource},
	}

	state := NewAnalyzerMemoryState(&types.AuthorizationAccountDetails{}, orgpolicies.NewDefaultOrgPolicies(), nil)
	actions := state.ExtractActions(&stmts)
	assert.Empty(t, actions)
}

func TestExtractActions_WildcardAction(t *testing.T) {
	// Wildcard actions like "iam:*" are expanded by the ActionExpander
	// which fetches from the embedded action list. We test that it returns
	// expanded actions.
	action := types.DynaString{"iam:*"}
	resource := types.DynaString{"*"}
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &action, Resource: &resource},
	}

	state := NewAnalyzerMemoryState(&types.AuthorizationAccountDetails{}, orgpolicies.NewDefaultOrgPolicies(), nil)
	actions := state.ExtractActions(&stmts)
	// The action expander for "iam:*" should return many iam:* actions
	// At minimum it should contain PassRole
	assert.Greater(t, len(actions), 0, "Expected wildcard action to be expanded")
}

// ---------------------------------------------------------------------------
// addServicesToResourceCache
// ---------------------------------------------------------------------------

func TestAddServicesToResourceCache(t *testing.T) {
	state := NewAnalyzerMemoryState(&types.AuthorizationAccountDetails{}, orgpolicies.NewDefaultOrgPolicies(), nil)

	// Check a few common services are in the cache
	services := []string{
		"s3.amazonaws.com",
		"lambda.amazonaws.com",
		"ec2.amazonaws.com",
		"iam.amazonaws.com",
		"kms.amazonaws.com",
	}

	for _, svc := range services {
		r := state.GetResource(svc)
		require.NotNil(t, r, "expected service %s to be in resource cache", svc)
		assert.Equal(t, "AWS::Service", r.ResourceType)
		assert.Equal(t, svc, r.ResourceID)
	}
}
