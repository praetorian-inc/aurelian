package serve

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGaadState_NilGaad(t *testing.T) {
	state := NewGaadState(nil, nil)
	require.NotNil(t, state)

	identity, boundary := state.LookupPrincipalStatements("arn:aws:iam::111111111111:user/nobody")
	assert.Nil(t, identity)
	assert.Nil(t, boundary)
}

func TestNewGaadState_UserStatements(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails(
		"111111111111",
		[]types.UserDetail{
			{
				Arn:      "arn:aws:iam::111111111111:user/admin",
				UserName: "admin",
				UserPolicyList: []types.InlinePolicy{
					{
						PolicyName: "AdminPolicy",
						PolicyDocument: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect:   "Allow",
									Action:   types.NewDynaString([]string{"*"}),
									Resource: types.NewDynaString([]string{"*"}),
								},
							},
						},
					},
				},
			},
		},
		nil, nil, nil,
	)

	state := NewGaadState(gaad, nil)

	identity, boundary := state.LookupPrincipalStatements("arn:aws:iam::111111111111:user/admin")
	require.NotNil(t, identity)
	assert.Nil(t, boundary)
	assert.Len(t, *identity, 1)
	assert.Equal(t, "Allow", (*identity)[0].Effect)
}

func TestNewGaadState_RoleStatements(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails(
		"111111111111",
		nil,
		nil,
		[]types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111111111111:role/MyRole",
				RoleName: "MyRole",
				RolePolicyList: []types.InlinePolicy{
					{
						PolicyName: "ReadOnly",
						PolicyDocument: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect:   "Allow",
									Action:   types.NewDynaString([]string{"s3:GetObject"}),
									Resource: types.NewDynaString([]string{"*"}),
								},
							},
						},
					},
				},
			},
		},
		nil,
	)

	state := NewGaadState(gaad, nil)

	identity, _ := state.LookupPrincipalStatements("arn:aws:iam::111111111111:role/MyRole")
	require.NotNil(t, identity)
	assert.Len(t, *identity, 1)
}

func TestNewGaadState_ManagedPolicy(t *testing.T) {
	policyArn := "arn:aws:iam::111111111111:policy/AdminAccess"
	gaad := types.NewAuthorizationAccountDetails(
		"111111111111",
		[]types.UserDetail{
			{
				Arn:      "arn:aws:iam::111111111111:user/managed-user",
				UserName: "managed-user",
				AttachedManagedPolicies: []types.ManagedPolicy{
					{PolicyArn: policyArn, PolicyName: "AdminAccess"},
				},
			},
		},
		nil,
		nil,
		[]types.ManagedPolicyDetail{
			{
				Arn:              policyArn,
				PolicyName:       "AdminAccess",
				DefaultVersionId: "v1",
				PolicyVersionList: []types.PolicyVersion{
					{
						VersionId:        "v1",
						IsDefaultVersion: true,
						Document: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect:   "Allow",
									Action:   types.NewDynaString([]string{"ec2:*"}),
									Resource: types.NewDynaString([]string{"*"}),
								},
							},
						},
					},
				},
			},
		},
	)

	state := NewGaadState(gaad, nil)

	identity, _ := state.LookupPrincipalStatements("arn:aws:iam::111111111111:user/managed-user")
	require.NotNil(t, identity)
	assert.Len(t, *identity, 1)
	assert.Equal(t, "Allow", (*identity)[0].Effect)
}

func TestNewGaadState_GroupPolicies(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails(
		"111111111111",
		[]types.UserDetail{
			{
				Arn:       "arn:aws:iam::111111111111:user/group-user",
				UserName:  "group-user",
				GroupList: []string{"Admins"},
			},
		},
		[]types.GroupDetail{
			{
				Arn:       "arn:aws:iam::111111111111:group/Admins",
				GroupName: "Admins",
				GroupPolicyList: []types.InlinePolicy{
					{
						PolicyName: "GroupAdmin",
						PolicyDocument: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect:   "Allow",
									Action:   types.NewDynaString([]string{"*"}),
									Resource: types.NewDynaString([]string{"*"}),
								},
							},
						},
					},
				},
			},
		},
		nil, nil,
	)

	state := NewGaadState(gaad, nil)

	identity, _ := state.LookupPrincipalStatements("arn:aws:iam::111111111111:user/group-user")
	require.NotNil(t, identity)
	assert.Len(t, *identity, 1, "should include group policy statements")
}

func TestNewGaadState_PermissionBoundary(t *testing.T) {
	boundaryArn := "arn:aws:iam::111111111111:policy/Boundary"
	gaad := types.NewAuthorizationAccountDetails(
		"111111111111",
		[]types.UserDetail{
			{
				Arn:      "arn:aws:iam::111111111111:user/bounded-user",
				UserName: "bounded-user",
				UserPolicyList: []types.InlinePolicy{
					{
						PolicyName: "AllAccess",
						PolicyDocument: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect:   "Allow",
									Action:   types.NewDynaString([]string{"*"}),
									Resource: types.NewDynaString([]string{"*"}),
								},
							},
						},
					},
				},
				PermissionsBoundary: types.ManagedPolicy{
					PolicyArn:  boundaryArn,
					PolicyName: "Boundary",
				},
			},
		},
		nil, nil,
		[]types.ManagedPolicyDetail{
			{
				Arn:              boundaryArn,
				PolicyName:       "Boundary",
				DefaultVersionId: "v1",
				PolicyVersionList: []types.PolicyVersion{
					{
						VersionId:        "v1",
						IsDefaultVersion: true,
						Document: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect:   "Allow",
									Action:   types.NewDynaString([]string{"s3:*"}),
									Resource: types.NewDynaString([]string{"*"}),
								},
							},
						},
					},
				},
			},
		},
	)

	state := NewGaadState(gaad, nil)

	identity, boundary := state.LookupPrincipalStatements("arn:aws:iam::111111111111:user/bounded-user")
	require.NotNil(t, identity)
	require.NotNil(t, boundary)
	assert.Len(t, *identity, 1)
	assert.Len(t, *boundary, 1)
}

func TestGaadState_GetResourceAccount(t *testing.T) {
	state := NewGaadState(nil, nil)

	// Valid ARN with account ID
	acct := state.GetResourceAccount("arn:aws:s3:us-east-1:123456789012:my-bucket")
	assert.Equal(t, "123456789012", acct)

	// S3 ARN without account (old-style)
	acct = state.GetResourceAccount("arn:aws:s3:::my-bucket")
	assert.Equal(t, "", acct)

	// Invalid ARN
	acct = state.GetResourceAccount("not-an-arn")
	assert.Equal(t, "", acct)
}

func TestNewGaadState_UnknownPrincipal(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)
	state := NewGaadState(gaad, nil)

	identity, boundary := state.LookupPrincipalStatements("arn:aws:iam::111111111111:user/nonexistent")
	assert.Nil(t, identity)
	assert.Nil(t, boundary)
}
