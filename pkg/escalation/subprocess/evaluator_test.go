package subprocess

import (
	"bytes"
	"encoding/json"
	"strings"
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

func TestEvaluator_collectStatementsForPrincipal(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)

	t.Run("resolves a user by ARN with its boundary", func(t *testing.T) {
		// Restricted has an inline Allow * and a DenyIAM permissions boundary.
		identity, boundary := eval.collectStatementsForPrincipal("arn:aws:iam::111111111111:user/Restricted")
		require.NotNil(t, identity)
		require.Len(t, *identity, 1)
		assert.Equal(t, "Allow", (*identity)[0].Effect)
		require.NotNil(t, boundary, "Restricted has a permissions boundary")
		require.Len(t, *boundary, 1)
		assert.Equal(t, "Deny", (*boundary)[0].Effect)
	})

	t.Run("resolves a user with a managed policy and no boundary", func(t *testing.T) {
		// Dev has the ReadOnly managed policy and no boundary.
		identity, boundary := eval.collectStatementsForPrincipal("arn:aws:iam::111111111111:user/Dev")
		require.NotNil(t, identity)
		require.Len(t, *identity, 1, "ReadOnly managed policy contributes one statement")
		assert.Equal(t, "Allow", (*identity)[0].Effect)
		assert.Nil(t, boundary, "Dev has no permissions boundary")
	})

	t.Run("resolves a role by ARN", func(t *testing.T) {
		identity, boundary := eval.collectStatementsForPrincipal("arn:aws:iam::111111111111:role/Admin")
		require.NotNil(t, identity)
		require.Len(t, *identity, 1)
		assert.Equal(t, "Allow", (*identity)[0].Effect)
		assert.Nil(t, boundary, "Admin has no permissions boundary")
	})

	t.Run("returns empty statements for an unknown principal", func(t *testing.T) {
		identity, boundary := eval.collectStatementsForPrincipal("arn:aws:iam::111111111111:role/DoesNotExist")
		require.NotNil(t, identity)
		assert.Empty(t, *identity)
		assert.Nil(t, boundary)
	})

	t.Run("does not match a role ARN against the users map", func(t *testing.T) {
		// A role ARN must resolve to the role's statements, never fall through
		// to an unrelated user. This pins the per-map keying so the O(1) Get
		// lookup stays equivalent to the original linear scan.
		identity, _ := eval.collectStatementsForPrincipal("arn:aws:iam::111111111111:role/Admin")
		require.NotNil(t, identity)
		require.Len(t, *identity, 1)
		assert.Equal(t, "Allow", (*identity)[0].Effect, "Admin role grants Allow *:*")
	})
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

func TestEvaluator_ListGrants(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)
	resp, err := eval.ListGrants()
	require.NoError(t, err)

	// Should have entries for all principals (2 users + 1 role)
	require.Len(t, resp.Entries, 3)

	byPrincipal := make(map[string]ListGrantsEntry)
	for _, e := range resp.Entries {
		byPrincipal[e.Principal] = e
	}

	// Admin role has Allow *:* — should appear as a statement
	admin := byPrincipal["arn:aws:iam::111111111111:role/Admin"]
	assert.NotEmpty(t, admin.EffectiveStatements)

	found := false
	for _, s := range admin.EffectiveStatements {
		if s.Effect == "Allow" && s.Action == "*" && s.Resource == "*" {
			found = true
		}
	}
	assert.True(t, found, "Admin should have Allow *:*")

	// Dev user has ReadOnly managed policy — should have s3:Get* / s3:List*
	dev := byPrincipal["arn:aws:iam::111111111111:user/Dev"]
	assert.NotEmpty(t, dev.EffectiveStatements)
}

func TestEvaluator_ListGrants_IncludesGroups(t *testing.T) {
	adminStmt := types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
	}
	gaad := types.NewAuthorizationAccountDetails("111111111111",
		nil, // no users
		[]types.GroupDetail{{
			Arn:       "arn:aws:iam::111111111111:group/Admins",
			GroupName: "Admins",
			GroupPolicyList: []types.InlinePolicy{
				{PolicyName: "Admin", PolicyDocument: types.Policy{Statement: &adminStmt}},
			},
		}},
		nil, // no roles
		nil,
	)
	eval := NewEvaluator(gaad, nil, nil)
	resp, err := eval.ListGrants()
	require.NoError(t, err)

	require.Len(t, resp.Entries, 1)
	assert.Equal(t, "arn:aws:iam::111111111111:group/Admins", resp.Entries[0].Principal)
	require.Len(t, resp.Entries[0].EffectiveStatements, 1)
	assert.Equal(t, "Allow", resp.Entries[0].EffectiveStatements[0].Effect)
}

func TestEvaluator_ListGrants_EmptyGAAD(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails("111111111111", nil, nil, nil, nil)
	eval := NewEvaluator(gaad, nil, nil)
	resp, err := eval.ListGrants()
	require.NoError(t, err)
	assert.Empty(t, resp.Entries)
}

func TestEvaluator_ListGrants_MixedAllowDeny(t *testing.T) {
	stmts := types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"s3:*"}, Resource: &types.DynaString{"*"}},
		{Effect: "Deny", Action: &types.DynaString{"s3:DeleteBucket"}, Resource: &types.DynaString{"*"}},
	}
	gaad := types.NewAuthorizationAccountDetails("111111111111",
		nil, nil,
		[]types.RoleDetail{{
			Arn:            "arn:aws:iam::111111111111:role/Mixed",
			RoleName:       "Mixed",
			RolePolicyList: []types.InlinePolicy{{PolicyName: "Mix", PolicyDocument: types.Policy{Statement: &stmts}}},
		}},
		nil,
	)
	eval := NewEvaluator(gaad, nil, nil)
	resp, err := eval.ListGrants()
	require.NoError(t, err)

	require.Len(t, resp.Entries, 1)
	allowCount := 0
	denyCount := 0
	for _, s := range resp.Entries[0].EffectiveStatements {
		switch s.Effect {
		case "Allow":
			allowCount++
		case "Deny":
			denyCount++
		}
	}
	assert.Equal(t, 1, allowCount, "should have 1 Allow")
	assert.Equal(t, 1, denyCount, "should have 1 Deny")
}

func TestListGrants_EndToEnd(t *testing.T) {
	eval := NewEvaluator(newTestGAAD(), nil, nil)
	input := `{"type":"list_grants"}` + "\n" + `{"type":"shutdown"}` + "\n"

	in := strings.NewReader(input)
	var out bytes.Buffer
	err := Serve(in, &out, eval)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 1)

	var resp ListGrantsResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))

	// 2 users + 1 role from newTestGAAD
	assert.Len(t, resp.Entries, 3)

	// Verify Admin has statements
	byPrincipal := make(map[string]ListGrantsEntry)
	for _, e := range resp.Entries {
		byPrincipal[e.Principal] = e
	}
	assert.NotEmpty(t, byPrincipal["arn:aws:iam::111111111111:role/Admin"].EffectiveStatements)
}

func TestWhoCanBulk_MixedResults(t *testing.T) {
	// Admin can do iam:PutRolePolicy, Dev cannot.
	eval := NewEvaluator(newTestGAAD(), nil, nil)

	// Run who_can_bulk through the protocol with the real evaluator.
	input := `{"type":"who_can_bulk","action":"iam:PutRolePolicy","targets":["arn:aws:iam::111111111111:role/Admin"],"principals":["arn:aws:iam::111111111111:role/Admin","arn:aws:iam::111111111111:user/Dev"]}` + "\n" + `{"type":"shutdown"}` + "\n"

	in := strings.NewReader(input)
	var out bytes.Buffer
	err := Serve(in, &out, eval)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 1)

	var resp WhoCanBulkResponse
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &resp))

	// Only Admin should be allowed; Dev should be denied (omitted).
	require.Len(t, resp.Grants, 1)
	assert.Equal(t, "arn:aws:iam::111111111111:role/Admin", resp.Grants[0].Principal)
	assert.Equal(t, "arn:aws:iam::111111111111:role/Admin", resp.Grants[0].Target)
	assert.Equal(t, "allowed", resp.Grants[0].Result)
}

// referenceWhoCanBulk reproduces the original per-call serial path: one
// CheckSpecific per (principal, target) cell. The hoisted Evaluator.WhoCanBulk
// must produce an identical grant set to this reference for any input.
func referenceWhoCanBulk(t *testing.T, e *Evaluator, action string, principals, targets []string) []Grant {
	t.Helper()
	var grants []Grant
	for _, principal := range principals {
		for _, target := range targets {
			resp, err := e.CheckSpecific(principal, action, target)
			require.NoError(t, err)
			if resp.Result == "allowed" {
				conditions := resp.Conditions
				if conditions == nil {
					conditions = []Condition{}
				}
				grants = append(grants, Grant{
					Principal:  principal,
					Target:     target,
					Result:     "allowed",
					Conditions: conditions,
				})
			}
		}
	}
	if grants == nil {
		grants = []Grant{}
	}
	return grants
}

// bulkFixtureGAAD builds an account that stresses every input dimension fix #2
// hoists out of the target loop, so the equivalence assertion can actually
// catch a hoisting bug:
//   - AdminUser:   inline Allow *:* (baseline, uniform across targets)
//   - ResUser:     resource-scoped Allow — grants differ PER TARGET, so any
//                  cross-target corruption of the reused statement slice flips
//                  a result. This is the key guard against unsafe slice reuse.
//   - BoundedUser: inline Allow *:* with a permissions boundary restricting to
//                  s3:* — exercises BOUNDARY hoisting (the second reused slice).
//   - GroupUser:   no inline policy; gets s3:List* via a group's managed policy
//                  — exercises group-walk + managed-policy resolution hoisting.
//   - CondUser:    conditional Allow — exercises the condition-bearing path.
//   - NoAccess:    no policies (denied everywhere).
func bulkFixtureGAAD() *types.AuthorizationAccountDetails {
	adminStmt := types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"*"}, Resource: &types.DynaString{"*"}},
	}
	// Resource-scoped: only objects under bucket-allowed are granted.
	resScopedStmt := types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"s3:GetObject"}, Resource: &types.DynaString{"arn:aws:s3:::bucket-allowed/*"}},
	}
	condStmt := types.PolicyStatementList{
		{
			Effect: "Allow", Action: &types.DynaString{"s3:GetObject"}, Resource: &types.DynaString{"*"},
			Condition: &types.Condition{"StringEquals": {"aws:username": {"CondUser"}}},
		},
	}
	s3BoundaryDoc := types.Policy{Statement: &types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"s3:*"}, Resource: &types.DynaString{"*"}},
	}}
	groupManagedDoc := types.Policy{Statement: &types.PolicyStatementList{
		{Effect: "Allow", Action: &types.DynaString{"s3:List*"}, Resource: &types.DynaString{"*"}},
	}}

	return types.NewAuthorizationAccountDetails("111111111111",
		[]types.UserDetail{
			{
				Arn: "arn:aws:iam::111111111111:user/AdminUser", UserName: "AdminUser",
				UserPolicyList: []types.InlinePolicy{{PolicyName: "Admin", PolicyDocument: types.Policy{Statement: &adminStmt}}},
			},
			{
				Arn: "arn:aws:iam::111111111111:user/ResUser", UserName: "ResUser",
				UserPolicyList: []types.InlinePolicy{{PolicyName: "ResScoped", PolicyDocument: types.Policy{Statement: &resScopedStmt}}},
			},
			{
				Arn: "arn:aws:iam::111111111111:user/BoundedUser", UserName: "BoundedUser",
				UserPolicyList: []types.InlinePolicy{{PolicyName: "Admin", PolicyDocument: types.Policy{Statement: &adminStmt}}},
				PermissionsBoundary: types.ManagedPolicy{
					PolicyName: "S3Boundary", PolicyArn: "arn:aws:iam::111111111111:policy/S3Boundary",
				},
			},
			{
				Arn: "arn:aws:iam::111111111111:user/GroupUser", UserName: "GroupUser",
				GroupList: []string{"S3Listers"},
			},
			{
				Arn: "arn:aws:iam::111111111111:user/CondUser", UserName: "CondUser",
				UserPolicyList: []types.InlinePolicy{{PolicyName: "Cond", PolicyDocument: types.Policy{Statement: &condStmt}}},
			},
			{Arn: "arn:aws:iam::111111111111:user/NoAccess", UserName: "NoAccess"},
		},
		[]types.GroupDetail{
			{
				Arn: "arn:aws:iam::111111111111:group/S3Listers", GroupName: "S3Listers",
				AttachedManagedPolicies: []types.ManagedPolicy{
					{PolicyName: "S3List", PolicyArn: "arn:aws:iam::111111111111:policy/S3List"},
				},
			},
		},
		[]types.RoleDetail{
			{
				Arn: "arn:aws:iam::111111111111:role/AdminRole", RoleName: "AdminRole",
				RolePolicyList: []types.InlinePolicy{{PolicyName: "Admin", PolicyDocument: types.Policy{Statement: &adminStmt}}},
			},
		},
		[]types.ManagedPolicyDetail{
			{
				Arn: "arn:aws:iam::111111111111:policy/S3Boundary", PolicyName: "S3Boundary",
				PolicyVersionList: []types.PolicyVersion{{VersionId: "v1", IsDefaultVersion: true, Document: s3BoundaryDoc}},
			},
			{
				Arn: "arn:aws:iam::111111111111:policy/S3List", PolicyName: "S3List",
				PolicyVersionList: []types.PolicyVersion{{VersionId: "v1", IsDefaultVersion: true, Document: groupManagedDoc}},
			},
		},
	)
}

func TestWhoCanBulk_EquivalentToSerialReference(t *testing.T) {
	eval := NewEvaluator(bulkFixtureGAAD(), nil, nil)

	principals := []string{
		"arn:aws:iam::111111111111:user/AdminUser",
		"arn:aws:iam::111111111111:user/ResUser",
		"arn:aws:iam::111111111111:user/BoundedUser",
		"arn:aws:iam::111111111111:user/GroupUser",
		"arn:aws:iam::111111111111:user/CondUser",
		"arn:aws:iam::111111111111:user/NoAccess",
		"arn:aws:iam::111111111111:role/AdminRole",
		"arn:aws:iam::111111111111:role/Missing", // unknown principal
	}
	// Multiple targets per principal, deliberately including ones that ResUser's
	// resource-scoped grant treats differently (bucket-allowed vs bucket-denied),
	// so a stale/shared statement slice across targets would change the result.
	targets := []string{
		"arn:aws:s3:::bucket-allowed/object.txt",
		"arn:aws:s3:::bucket-denied/object.txt",
		"arn:aws:s3:::bucket-allowed/other.txt",
		"arn:aws:iam::111111111111:role/AdminRole",
		"arn:aws:iam::111111111111:user/AdminUser",
	}

	// Run for several actions so allow/deny patterns differ per cell, including
	// iam:* (denied by BoundedUser's boundary but allowed by AdminUser).
	for _, action := range []string{"iam:PutRolePolicy", "s3:GetObject", "s3:ListBucket", "ec2:RunInstances"} {
		t.Run(action, func(t *testing.T) {
			want := referenceWhoCanBulk(t, eval, action, principals, targets)
			got, err := eval.WhoCanBulk(action, principals, targets)
			require.NoError(t, err)
			// Identical content and order: WhoCanBulk must iterate
			// principals-outer, targets-inner just like the reference.
			assert.Equal(t, want, got)
		})
	}
}

// TestWhoCanBulk_FixtureExercisesDivergence guards the guard: it asserts the
// fixture actually produces per-target divergence and boundary-driven denials,
// so the equivalence test above has something a hoisting bug could break. If
// this fails, the fixture has gone uniform and the equivalence test is toothless.
func TestWhoCanBulk_FixtureExercisesDivergence(t *testing.T) {
	eval := NewEvaluator(bulkFixtureGAAD(), nil, nil)

	// ResUser: same principal, same action, different target → different result.
	allowed, err := eval.CheckSpecific("arn:aws:iam::111111111111:user/ResUser", "s3:GetObject", "arn:aws:s3:::bucket-allowed/x")
	require.NoError(t, err)
	denied, err := eval.CheckSpecific("arn:aws:iam::111111111111:user/ResUser", "s3:GetObject", "arn:aws:s3:::bucket-denied/x")
	require.NoError(t, err)
	require.Equal(t, "allowed", allowed.Result, "ResUser must be allowed on bucket-allowed")
	require.Equal(t, "denied", denied.Result, "ResUser must be denied on bucket-denied — this is the per-target divergence")

	// BoundedUser: Allow *:* but S3 boundary → s3 allowed, iam denied.
	s3ok, err := eval.CheckSpecific("arn:aws:iam::111111111111:user/BoundedUser", "s3:GetObject", "arn:aws:s3:::bucket-allowed/x")
	require.NoError(t, err)
	iamno, err := eval.CheckSpecific("arn:aws:iam::111111111111:user/BoundedUser", "iam:PutRolePolicy", "arn:aws:iam::111111111111:role/AdminRole")
	require.NoError(t, err)
	require.Equal(t, "allowed", s3ok.Result, "BoundedUser s3 within boundary")
	require.Equal(t, "denied", iamno.Result, "BoundedUser iam blocked by boundary — exercises boundary hoisting")

	// GroupUser: access only via group's managed policy.
	grp, err := eval.CheckSpecific("arn:aws:iam::111111111111:user/GroupUser", "s3:ListBucket", "arn:aws:s3:::bucket-allowed")
	require.NoError(t, err)
	require.Equal(t, "allowed", grp.Result, "GroupUser s3:List via group managed policy — exercises group/managed hoisting")
}

func TestWhoCanBulk_EmptyInputs(t *testing.T) {
	eval := NewEvaluator(bulkFixtureGAAD(), nil, nil)

	got, err := eval.WhoCanBulk("s3:GetObject", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, []Grant{}, got, "no principals/targets yields an empty, non-nil slice")
}

// TestWhoCanBulk_PropagatesEvaluationError pins that a per-cell evaluation
// error surfaces from WhoCanBulk (rather than being swallowed or producing a
// partial grant set). An unparseable target ARN fails request-context setup.
func TestWhoCanBulk_PropagatesEvaluationError(t *testing.T) {
	eval := NewEvaluator(bulkFixtureGAAD(), nil, nil)

	principals := []string{"arn:aws:iam::111111111111:user/AdminUser"}
	targets := []string{"not-a-valid-arn"}

	got, err := eval.WhoCanBulk("s3:GetObject", principals, targets)
	require.Error(t, err, "an unparseable target ARN must surface as an error")
	assert.Nil(t, got, "no partial grants on error")
	assert.Contains(t, err.Error(), "not-a-valid-arn", "error should identify the offending cell")
}

// TestWhoCanBulk_ParallelMatchesSerial proves the worker-pool path produces a
// byte-identical grant set to the serial reference for any worker count. Run
// under `go test -race` this also exercises the concurrency-safety claim:
// Evaluate over a frozen GAAD plus read-only reuse of per-principal statements.
func TestWhoCanBulk_ParallelMatchesSerial(t *testing.T) {
	eval := NewEvaluator(bulkFixtureGAAD(), nil, nil)

	principals := []string{
		"arn:aws:iam::111111111111:user/AdminUser",
		"arn:aws:iam::111111111111:user/ResUser",
		"arn:aws:iam::111111111111:user/BoundedUser",
		"arn:aws:iam::111111111111:user/GroupUser",
		"arn:aws:iam::111111111111:user/CondUser",
		"arn:aws:iam::111111111111:user/NoAccess",
		"arn:aws:iam::111111111111:role/AdminRole",
		"arn:aws:iam::111111111111:role/Missing",
	}
	targets := []string{
		"arn:aws:s3:::bucket-allowed/object.txt",
		"arn:aws:s3:::bucket-denied/object.txt",
		"arn:aws:s3:::bucket-allowed/other.txt",
		"arn:aws:iam::111111111111:role/AdminRole",
		"arn:aws:iam::111111111111:user/AdminUser",
	}

	for _, workers := range []string{"1", "2", "4", "8", "100"} {
		t.Run("workers="+workers, func(t *testing.T) {
			t.Setenv("AURELIAN_EVAL_WORKERS", workers)
			for _, action := range []string{"iam:PutRolePolicy", "s3:GetObject", "s3:ListBucket", "ec2:RunInstances"} {
				want := referenceWhoCanBulk(t, eval, action, principals, targets)
				got, err := eval.WhoCanBulk(action, principals, targets)
				require.NoError(t, err)
				assert.Equal(t, want, got, "parallel output must match serial reference exactly, including order")
			}
		})
	}
}

// TestWhoCanBulk_ParallelPropagatesError confirms an error in any cell still
// surfaces (and yields no partial grants) when running with multiple workers.
func TestWhoCanBulk_ParallelPropagatesError(t *testing.T) {
	t.Setenv("AURELIAN_EVAL_WORKERS", "8")
	eval := NewEvaluator(bulkFixtureGAAD(), nil, nil)

	principals := []string{
		"arn:aws:iam::111111111111:user/AdminUser",
		"arn:aws:iam::111111111111:user/ResUser",
	}
	targets := []string{
		"arn:aws:s3:::bucket-allowed/x",
		"not-a-valid-arn", // one bad cell among many
		"arn:aws:s3:::bucket-allowed/y",
	}

	got, err := eval.WhoCanBulk("s3:GetObject", principals, targets)
	require.Error(t, err)
	assert.Nil(t, got, "no partial grants on error")
	assert.Contains(t, err.Error(), "not-a-valid-arn")
}

// benchGAAD builds a managed-policy- and group-heavy account: the realistic
// shape where per-principal statement collection (managed-policy resolution +
// group walking) is expensive, so hoisting it out of the target loop matters.
func benchGAAD(nUsers, nManaged int) *types.AuthorizationAccountDetails {
	managed := make([]types.ManagedPolicyDetail, nManaged)
	attached := make([]types.ManagedPolicy, nManaged)
	for i := 0; i < nManaged; i++ {
		arn := "arn:aws:iam::111111111111:policy/Managed" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		doc := types.Policy{Statement: &types.PolicyStatementList{
			{Effect: "Allow", Action: &types.DynaString{"s3:Get*", "s3:List*"}, Resource: &types.DynaString{"*"}},
		}}
		managed[i] = types.ManagedPolicyDetail{
			Arn: arn, PolicyName: "Managed" + string(rune('A'+i%26)),
			PolicyVersionList: []types.PolicyVersion{{VersionId: "v1", IsDefaultVersion: true, Document: doc}},
		}
		attached[i] = types.ManagedPolicy{PolicyName: managed[i].PolicyName, PolicyArn: arn}
	}

	group := types.GroupDetail{
		Arn: "arn:aws:iam::111111111111:group/Eng", GroupName: "Eng",
		AttachedManagedPolicies: attached,
	}

	users := make([]types.UserDetail, nUsers)
	for i := 0; i < nUsers; i++ {
		users[i] = types.UserDetail{
			Arn:                     "arn:aws:iam::111111111111:user/U" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			UserName:                "U" + string(rune('a'+i%26)),
			AttachedManagedPolicies: attached,
			GroupList:               []string{"Eng"},
		}
	}
	return types.NewAuthorizationAccountDetails("111111111111", users, []types.GroupDetail{group}, nil, managed)
}

func benchInputs(gaad *types.AuthorizationAccountDetails) (principals, targets []string) {
	gaad.Users.Range(func(_ string, u types.UserDetail) bool {
		principals = append(principals, u.Arn)
		return true
	})
	for i := 0; i < 200; i++ {
		targets = append(targets, "arn:aws:s3:::bucket-"+string(rune('a'+i%26))+"/key")
	}
	return principals, targets
}

func BenchmarkWhoCanBulk(b *testing.B) {
	eval := NewEvaluator(benchGAAD(10, 8), nil, nil)
	principals, targets := benchInputs(eval.gaad)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eval.WhoCanBulk("s3:GetObject", principals, targets); err != nil {
			b.Fatal(err)
		}
	}
}
