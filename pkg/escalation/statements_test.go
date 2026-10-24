package escalation

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// testGAAD builds a GAAD with a user, role, group, and managed policies for
// statement-walking tests.
func testGAAD() *types.AuthorizationAccountDetails {
	// Managed policies
	managedPolicy := types.ManagedPolicyDetail{
		Arn:              "arn:aws:iam::123456789012:policy/ReadOnly",
		DefaultVersionId: "v1",
		PolicyVersionList: []types.PolicyVersion{
			{
				IsDefaultVersion: true,
				Document: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{Effect: "Allow", Action: strSlice("s3:GetObject"), Resource: strSlice("*")},
					},
				},
			},
		},
	}

	secondPolicy := types.ManagedPolicyDetail{
		Arn:              "arn:aws:iam::123456789012:policy/Admin",
		DefaultVersionId: "v1",
		PolicyVersionList: []types.PolicyVersion{
			{
				IsDefaultVersion: true,
				Document: types.Policy{
					Version: "2012-10-17",
					Statement: &types.PolicyStatementList{
						{Effect: "Allow", Action: strSlice("*"), Resource: strSlice("*")},
					},
				},
			},
		},
	}

	policies := store.NewMap[types.ManagedPolicyDetail]()
	policies.Set(managedPolicy.Arn, managedPolicy)
	policies.Set(secondPolicy.Arn, secondPolicy)

	// Group
	group := types.GroupDetail{
		Arn:       "arn:aws:iam::123456789012:group/devs",
		GroupName: "devs",
		GroupPolicyList: []types.InlinePolicy{
			{
				PolicyName: "group-inline",
				PolicyDocument: types.Policy{
					Statement: &types.PolicyStatementList{
						{Effect: "Allow", Action: strSlice("ec2:Describe*"), Resource: strSlice("*")},
					},
				},
			},
		},
		AttachedManagedPolicies: []types.ManagedPolicy{
			{PolicyArn: managedPolicy.Arn, PolicyName: "ReadOnly"},
		},
	}

	groups := store.NewMap[types.GroupDetail]()
	groups.Set(group.Arn, group)

	// Role
	role := types.RoleDetail{
		Arn:      "arn:aws:iam::123456789012:role/lambda-exec",
		RoleName: "lambda-exec",
		RolePolicyList: []types.InlinePolicy{
			{
				PolicyName: "role-inline",
				PolicyDocument: types.Policy{
					Statement: &types.PolicyStatementList{
						{Effect: "Allow", Action: strSlice("logs:PutLogEvents"), Resource: strSlice("*")},
					},
				},
			},
		},
		AttachedManagedPolicies: []types.ManagedPolicy{
			{PolicyArn: secondPolicy.Arn, PolicyName: "Admin"},
		},
	}

	roles := store.NewMap[types.RoleDetail]()
	roles.Set(role.Arn, role)

	// User
	user := types.UserDetail{
		Arn:      "arn:aws:iam::123456789012:user/alice",
		UserName: "alice",
		UserPolicyList: []types.InlinePolicy{
			{
				PolicyName: "user-inline",
				PolicyDocument: types.Policy{
					Statement: &types.PolicyStatementList{
						{Effect: "Deny", Action: strSlice("iam:*"), Resource: strSlice("*")},
					},
				},
			},
		},
		AttachedManagedPolicies: []types.ManagedPolicy{
			{PolicyArn: managedPolicy.Arn, PolicyName: "ReadOnly"},
		},
		GroupList: []string{"devs"},
	}

	users := store.NewMap[types.UserDetail]()
	users.Set(user.Arn, user)

	return &types.AuthorizationAccountDetails{
		Users:    users,
		Roles:    roles,
		Groups:   groups,
		Policies: policies,
	}
}

// strSlice is a shorthand for constructing *types.DynaString.
func strSlice(s ...string) *types.DynaString {
	ds := types.DynaString(s)
	return &ds
}

func TestWalkRoleStatements(t *testing.T) {
	gaad := testGAAD()
	role, ok := gaad.Roles.Get("arn:aws:iam::123456789012:role/lambda-exec")
	if !ok {
		t.Fatal("role not found")
	}
	resolver := GAADPolicyResolver(gaad)

	var origins []PolicyOrigin
	var stmts []types.PolicyStatement
	WalkRoleStatements(&role, resolver, func(origin PolicyOrigin, s types.PolicyStatement) {
		origins = append(origins, origin)
		stmts = append(stmts, s)
	})

	// Expect: 1 inline + 1 managed
	if got := len(stmts); got != 2 {
		t.Fatalf("expected 2 statements, got %d", got)
	}

	// First should be inline
	if origins[0].Type != OriginInline {
		t.Errorf("first origin type = %q, want %q", origins[0].Type, OriginInline)
	}
	if origins[0].PolicyName != "role-inline" {
		t.Errorf("first origin policy name = %q, want %q", origins[0].PolicyName, "role-inline")
	}
	if origins[0].PrincipalName != "lambda-exec" {
		t.Errorf("first origin principal name = %q, want %q", origins[0].PrincipalName, "lambda-exec")
	}

	// Second should be managed
	if origins[1].Type != OriginManaged {
		t.Errorf("second origin type = %q, want %q", origins[1].Type, OriginManaged)
	}
	if origins[1].PolicyARN != "arn:aws:iam::123456789012:policy/Admin" {
		t.Errorf("second origin policy ARN = %q, want admin policy ARN", origins[1].PolicyARN)
	}
}

func TestWalkGroupStatements(t *testing.T) {
	gaad := testGAAD()
	group, ok := gaad.Groups.Get("arn:aws:iam::123456789012:group/devs")
	if !ok {
		t.Fatal("group not found")
	}
	resolver := GAADPolicyResolver(gaad)

	var origins []PolicyOrigin
	var stmts []types.PolicyStatement
	WalkGroupStatements(&group, resolver, func(origin PolicyOrigin, s types.PolicyStatement) {
		origins = append(origins, origin)
		stmts = append(stmts, s)
	})

	// Expect: 1 inline + 1 managed
	if got := len(stmts); got != 2 {
		t.Fatalf("expected 2 statements, got %d", got)
	}
	if origins[0].Type != OriginInline {
		t.Errorf("origin[0].Type = %q, want %q", origins[0].Type, OriginInline)
	}
	if origins[0].PrincipalType != "group" {
		t.Errorf("origin[0].PrincipalType = %q, want group", origins[0].PrincipalType)
	}
	if origins[1].Type != OriginManaged {
		t.Errorf("origin[1].Type = %q, want %q", origins[1].Type, OriginManaged)
	}
}

func TestWalkUserStatements(t *testing.T) {
	gaad := testGAAD()
	user, ok := gaad.Users.Get("arn:aws:iam::123456789012:user/alice")
	if !ok {
		t.Fatal("user not found")
	}
	groupsByName := BuildGroupsByName(gaad)
	resolver := GAADPolicyResolver(gaad)

	var origins []PolicyOrigin
	var stmts []types.PolicyStatement
	WalkUserStatements(&user, groupsByName, resolver, func(origin PolicyOrigin, s types.PolicyStatement) {
		origins = append(origins, origin)
		stmts = append(stmts, s)
	})

	// Expect: 1 user-inline + 1 user-managed + 1 group-inline + 1 group-managed = 4
	if got := len(stmts); got != 4 {
		t.Fatalf("expected 4 statements, got %d", got)
	}

	// Check user inline
	if origins[0].Type != OriginInline {
		t.Errorf("origin[0] = %q, want inline", origins[0].Type)
	}
	if origins[0].PrincipalType != "user" {
		t.Errorf("origin[0].PrincipalType = %q, want user", origins[0].PrincipalType)
	}

	// Check user managed
	if origins[1].Type != OriginManaged {
		t.Errorf("origin[1] = %q, want managed", origins[1].Type)
	}

	// Check group inline
	if origins[2].Type != OriginInline {
		t.Errorf("origin[2] = %q, want inline", origins[2].Type)
	}
	if origins[2].PrincipalType != "group" {
		t.Errorf("origin[2].PrincipalType = %q, want group", origins[2].PrincipalType)
	}
	if origins[2].PrincipalName != "devs" {
		t.Errorf("origin[2].PrincipalName = %q, want devs", origins[2].PrincipalName)
	}

	// Check group managed
	if origins[3].Type != OriginManaged {
		t.Errorf("origin[3] = %q, want managed", origins[3].Type)
	}
}

func TestWalkUserStatements_MissingGroup(t *testing.T) {
	gaad := testGAAD()
	// Create a user that references a non-existent group.
	user := types.UserDetail{
		Arn:       "arn:aws:iam::123456789012:user/orphan",
		UserName:  "orphan",
		GroupList: []string{"does-not-exist"},
	}
	groupsByName := BuildGroupsByName(gaad)
	resolver := GAADPolicyResolver(gaad)

	var count int
	WalkUserStatements(&user, groupsByName, resolver, func(_ PolicyOrigin, _ types.PolicyStatement) {
		count++
	})
	if count != 0 {
		t.Errorf("expected 0 statements for orphan user, got %d", count)
	}
}

func TestWalkUserStatements_MissingManagedPolicy(t *testing.T) {
	// User references a managed policy that doesn't exist in GAAD.
	policies := store.NewMap[types.ManagedPolicyDetail]()
	groups := store.NewMap[types.GroupDetail]()
	roles := store.NewMap[types.RoleDetail]()
	users := store.NewMap[types.UserDetail]()

	user := types.UserDetail{
		Arn:      "arn:aws:iam::123456789012:user/bob",
		UserName: "bob",
		AttachedManagedPolicies: []types.ManagedPolicy{
			{PolicyArn: "arn:aws:iam::123456789012:policy/ghost"},
		},
	}
	users.Set(user.Arn, user)

	gaad := &types.AuthorizationAccountDetails{
		Users: users, Roles: roles, Groups: groups, Policies: policies,
	}
	resolver := GAADPolicyResolver(gaad)

	var count int
	WalkUserStatements(&user, map[string]types.GroupDetail{}, resolver, func(_ PolicyOrigin, _ types.PolicyStatement) {
		count++
	})
	if count != 0 {
		t.Errorf("expected 0 statements for missing managed policy, got %d", count)
	}
}

func TestCollectRawStatements_Role(t *testing.T) {
	gaad := testGAAD()
	role, ok := gaad.Roles.Get("arn:aws:iam::123456789012:role/lambda-exec")
	if !ok {
		t.Fatal("role not found")
	}
	resolver := GAADPolicyResolver(gaad)

	stmts := CollectRawRoleStatements(&role, resolver)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
}

func TestCollectRawStatements_User(t *testing.T) {
	gaad := testGAAD()
	user, ok := gaad.Users.Get("arn:aws:iam::123456789012:user/alice")
	if !ok {
		t.Fatal("user not found")
	}
	groupsByName := BuildGroupsByName(gaad)
	resolver := GAADPolicyResolver(gaad)

	stmts := CollectRawUserStatements(&user, groupsByName, resolver)
	// 1 user-inline + 1 user-managed + 1 group-inline + 1 group-managed = 4
	if len(stmts) != 4 {
		t.Fatalf("expected 4 statements, got %d", len(stmts))
	}
}

func TestCollectRawStatements_Group(t *testing.T) {
	gaad := testGAAD()
	group, ok := gaad.Groups.Get("arn:aws:iam::123456789012:group/devs")
	if !ok {
		t.Fatal("group not found")
	}
	resolver := GAADPolicyResolver(gaad)

	stmts := CollectRawGroupStatements(&group, resolver)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
}
