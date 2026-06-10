package subprocess

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGAAD() *types.AuthorizationAccountDetails {
	adminStmt := types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
	}
	adminPolicy := types.Policy{Statement: &adminStmt}

	denyStmt := types.PolicyStatementList{
		{Effect: "Deny", Action: &types.DynaString{"iam:*"}, Resource: &types.DynaString{"*"}},
	}
	denyPolicy := types.Policy{Statement: &denyStmt}

	trustStmt := types.PolicyStatementList{
		{
			Effect:    "Allow",
			Principal: &types.Principal{AWS: &types.DynaString{"arn:aws:iam::111111111111:user/Dev"}},
			Action:    &types.DynaString{"sts:AssumeRole"},
			Resource:  &types.DynaString{"arn:aws:iam::111111111111:role/Admin"},
		},
	}
	trustPolicy := types.Policy{Statement: &trustStmt}

	readOnlyStmt := types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"s3:Get*", "s3:List*"}, Resource: &types.DynaString{"arn:aws:s3:::my-bucket/*"}},
	}
	readOnlyPolicy := types.Policy{Statement: &readOnlyStmt}

	return types.NewAuthorizationAccountDetails("111111111111",
		[]types.UserDetail{
			{
				Arn:      "arn:aws:iam::111111111111:user/Dev",
				UserName: "Dev",
				AttachedManagedPolicies: []types.ManagedPolicy{
					{PolicyName: "ReadOnly", PolicyArn: "arn:aws:iam::111111111111:policy/ReadOnly"},
				},
			},
			{
				Arn:      "arn:aws:iam::111111111111:user/Restricted",
				UserName: "Restricted",
				UserPolicyList: []types.InlinePolicy{
					{PolicyName: "AllowAll", PolicyDocument: adminPolicy},
				},
				PermissionsBoundary: types.ManagedPolicy{
					PolicyName: "DenyIAM",
					PolicyArn:  "arn:aws:iam::111111111111:policy/DenyIAM",
				},
			},
		},
		nil,
		[]types.RoleDetail{
			{
				Arn:      "arn:aws:iam::111111111111:role/Admin",
				RoleName: "Admin",
				RolePolicyList: []types.InlinePolicy{
					{PolicyName: "AdminAccess", PolicyDocument: adminPolicy},
				},
				AssumeRolePolicyDocument: trustPolicy,
			},
		},
		[]types.ManagedPolicyDetail{
			{
				Arn:        "arn:aws:iam::111111111111:policy/ReadOnly",
				PolicyName: "ReadOnly",
				PolicyVersionList: []types.PolicyVersion{
					{VersionId: "v1", IsDefaultVersion: true, Document: readOnlyPolicy},
				},
			},
			{
				Arn:        "arn:aws:iam::111111111111:policy/DenyIAM",
				PolicyName: "DenyIAM",
				PolicyVersionList: []types.PolicyVersion{
					{VersionId: "v1", IsDefaultVersion: true, Document: denyPolicy},
				},
			},
		},
	)
}

func TestEvaluator_CheckSpecific_AdminAllowed(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)
	resp, err := eval.CheckSpecific(
		"arn:aws:iam::111111111111:role/Admin",
		"iam:PutRolePolicy",
		"arn:aws:iam::111111111111:role/TargetRole",
	)
	require.NoError(t, err)
	assert.Equal(t, "allowed", resp.Result)
}

func TestEvaluator_CheckSpecific_ReadOnlyDenied(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)
	resp, err := eval.CheckSpecific(
		"arn:aws:iam::111111111111:user/Dev",
		"iam:PutRolePolicy",
		"arn:aws:iam::111111111111:role/TargetRole",
	)
	require.NoError(t, err)
	assert.Equal(t, "denied", resp.Result)
}

func TestEvaluator_CheckSpecific_ReadOnlyS3Allowed(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)
	resp, err := eval.CheckSpecific(
		"arn:aws:iam::111111111111:user/Dev",
		"s3:GetObject",
		"arn:aws:s3:::my-bucket/file.txt",
	)
	require.NoError(t, err)
	assert.Equal(t, "allowed", resp.Result)
}

func TestEvaluator_CheckAnyTarget(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)
	resp, err := eval.CheckAnyTarget(
		"arn:aws:iam::111111111111:role/Admin",
		"iam:PutRolePolicy",
	)
	require.NoError(t, err)
	assert.Equal(t, "allowed", resp.Result)
}

func TestEvaluator_CheckAnyTarget_Denied(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)
	resp, err := eval.CheckAnyTarget(
		"arn:aws:iam::111111111111:user/Dev",
		"iam:PutRolePolicy",
	)
	require.NoError(t, err)
	assert.Equal(t, "denied", resp.Result)
}

func TestEvaluator_CheckAnyTarget_ResourceConstraint(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)
	resp, err := eval.CheckAnyTarget(
		"arn:aws:iam::111111111111:user/Dev",
		"s3:GetObject",
	)
	require.NoError(t, err)
	assert.Equal(t, "allowed", resp.Result)
	require.NotNil(t, resp.ResourceConstraint)
	assert.Equal(t, "arn:aws:s3:::my-bucket/*", *resp.ResourceConstraint)
}

func TestEvaluator_CheckCounterfactual(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)

	// User Restricted has Allow * but a DenyIAM boundary.
	// With the deny removed, iam:PutRolePolicy should be allowed.
	resp, err := eval.CheckCounterfactual(
		"arn:aws:iam::111111111111:user/Restricted",
		"iam:PutRolePolicy",
		"arn:aws:iam::111111111111:role/TargetRole",
		[]RemovedStatement{{Effect: "Deny", Action: "iam:*", Resource: "*"}},
	)
	require.NoError(t, err)
	assert.Equal(t, "allowed", resp.Result)
}

func TestEvaluator_UnknownPrincipal(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)
	resp, err := eval.CheckSpecific(
		"arn:aws:iam::111111111111:role/NonExistent",
		"s3:GetObject",
		"arn:aws:s3:::bucket/key",
	)
	require.NoError(t, err)
	assert.Equal(t, "denied", resp.Result)
}

func TestFilterRemovedStatements(t *testing.T) {
	stmts := &types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"s3:*"}, Resource: &types.DynaString{"*"}},
		{Effect: "Deny", Action: &types.DynaString{"iam:*"}, Resource: &types.DynaString{"*"}},
		{Effect: "Deny", Action: &types.DynaString{"s3:DeleteBucket"}, Resource: &types.DynaString{"*"}},
	}

	removed := []RemovedStatement{
		{Effect: "Deny", Action: "iam:*", Resource: "*"},
	}

	filtered := filterRemovedStatements(stmts, removed)
	require.Len(t, *filtered, 2, "should remove the iam:* deny but keep others")
	assert.Equal(t, "Allow", (*filtered)[0].Effect)
	assert.Equal(t, "Deny", (*filtered)[1].Effect)
	assert.Equal(t, "s3:DeleteBucket", (*(*filtered)[1].Action)[0])
}

func TestEvaluator_WithResourcePolicy(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111",
		nil,
		nil,
		[]types.RoleDetail{
			{Arn: "arn:aws:iam::111111111111:role/NoIdentityPolicy", RoleName: "NoIdentityPolicy"},
		},
		nil,
	)

	// Resource policy grants the role access. The evaluator looks up resource
	// policies by exact target ARN, so we use the target ARN as the map key.
	bucketPolicy := &types.Policy{
		Statement: &types.PolicyStatementList{
			{
				Effect:    "Allow",
				Principal: &types.Principal{AWS: &types.DynaString{"arn:aws:iam::111111111111:role/NoIdentityPolicy"}},
				Action:    &types.DynaString{"s3:GetObject"},
				Resource:  &types.DynaString{"arn:aws:s3:::my-bucket"},
			},
		},
	}
	resourcePolicies := map[string]*types.Policy{
		"arn:aws:s3:::my-bucket": bucketPolicy,
	}

	eval := NewEvaluator(gaad, nil, resourcePolicies)

	// The role has no identity policy but the bucket policy grants access.
	resp, err := eval.CheckSpecific(
		"arn:aws:iam::111111111111:role/NoIdentityPolicy",
		"s3:GetObject",
		"arn:aws:s3:::my-bucket",
	)
	require.NoError(t, err)
	// Same-account: resource policy with explicit principal allow → allowed
	assert.Equal(t, "allowed", resp.Result)
}
