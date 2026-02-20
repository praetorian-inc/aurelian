//go:build integration

package gaad

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGAAD(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/graph")
	fixture.Setup()

	g := New(plugin.AWSReconBase{})
	result, err := g.Get()
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Run("account ID is populated", func(t *testing.T) {
		assert.NotEmpty(t, result.AccountID, "account ID should be set")
	})

	t.Run("users are collected", func(t *testing.T) {
		userNames := fixture.OutputList("user_names")

		foundUsers := make(map[string]bool)
		for _, u := range result.UserDetailList {
			foundUsers[u.UserName] = true
		}

		for _, name := range userNames {
			assert.True(t, foundUsers[name], "GAAD should contain user %s", name)
		}
	})

	t.Run("groups are collected", func(t *testing.T) {
		groupName := fixture.Output("group_name")

		foundGroups := make(map[string]bool)
		for _, g := range result.GroupDetailList {
			foundGroups[g.GroupName] = true
		}

		assert.True(t, foundGroups[groupName], "GAAD should contain group %s", groupName)
	})

	t.Run("roles are collected", func(t *testing.T) {
		lambdaRoleName := fixture.Output("lambda_role_name")
		assumableRoleName := fixture.Output("assumable_role_name")

		foundRoles := make(map[string]bool)
		for _, r := range result.RoleDetailList {
			foundRoles[r.RoleName] = true
		}

		assert.True(t, foundRoles[lambdaRoleName], "GAAD should contain role %s", lambdaRoleName)
		assert.True(t, foundRoles[assumableRoleName], "GAAD should contain role %s", assumableRoleName)
	})

	t.Run("managed policies are collected", func(t *testing.T) {
		customPolicyARN := fixture.Output("custom_policy_arn")

		foundPolicies := make(map[string]bool)
		for _, p := range result.Policies {
			foundPolicies[p.Arn] = true
		}

		assert.True(t, foundPolicies[customPolicyARN], "GAAD should contain policy %s", customPolicyARN)
	})

	t.Run("inline policies are present on users", func(t *testing.T) {
		userNames := fixture.OutputList("user_names")

		// user 0 should have an inline policy
		for _, u := range result.UserDetailList {
			if u.UserName == userNames[0] {
				assert.NotEmpty(t, u.UserPolicyList, "user %s should have inline policies", u.UserName)
				return
			}
		}
		t.Errorf("user %s not found in GAAD results", userNames[0])
	})

	t.Run("group memberships are present", func(t *testing.T) {
		userNames := fixture.OutputList("user_names")
		groupName := fixture.Output("group_name")

		// user 0 should be a member of the test group
		for _, u := range result.UserDetailList {
			if u.UserName == userNames[0] {
				assert.Contains(t, u.GroupList, groupName, "user %s should be in group %s", u.UserName, groupName)
				return
			}
		}
		t.Errorf("user %s not found in GAAD results", userNames[0])
	})

	t.Run("role trust policies are present", func(t *testing.T) {
		lambdaRoleName := fixture.Output("lambda_role_name")

		for _, r := range result.RoleDetailList {
			if r.RoleName == lambdaRoleName {
				assert.NotEmpty(t, r.AssumeRolePolicyDocument.Statement,
					"role %s should have a trust policy with statements", r.RoleName)
				return
			}
		}
		t.Errorf("role %s not found in GAAD results", lambdaRoleName)
	})

	t.Run("managed policy versions are present", func(t *testing.T) {
		customPolicyARN := fixture.Output("custom_policy_arn")

		for _, p := range result.Policies {
			if p.Arn == customPolicyARN {
				assert.NotEmpty(t, p.PolicyVersionList, "policy %s should have versions", p.Arn)
				doc := p.DefaultPolicyDocument()
				assert.NotNil(t, doc, "policy %s should have a default version document", p.Arn)
				return
			}
		}
		t.Errorf("policy %s not found in GAAD results", customPolicyARN)
	})

	t.Run("matches legacy GetAccountAuthorizationDetails", func(t *testing.T) {
		opts := plugin.AWSReconBase{}
		legacyResult, legacyAccountID, err := GetAccountAuthorizationDetails(context.Background(), opts)
		require.NoError(t, err)

		assert.Equal(t, result.AccountID, legacyAccountID, "account IDs should match")

		// Compare users by ARN
		legacyUserARNs := make(map[string]bool)
		for _, u := range legacyResult.UserDetailList {
			legacyUserARNs[u.Arn] = true
		}
		newUserARNs := make(map[string]bool)
		for _, u := range result.UserDetailList {
			newUserARNs[u.Arn] = true
		}
		assert.Equal(t, legacyUserARNs, newUserARNs, "user ARNs should match")

		// Compare groups by ARN
		legacyGroupARNs := make(map[string]bool)
		for _, g := range legacyResult.GroupDetailList {
			legacyGroupARNs[g.Arn] = true
		}
		newGroupARNs := make(map[string]bool)
		for _, g := range result.GroupDetailList {
			newGroupARNs[g.Arn] = true
		}
		assert.Equal(t, legacyGroupARNs, newGroupARNs, "group ARNs should match")

		// Compare roles by ARN
		legacyRoleARNs := make(map[string]bool)
		for _, r := range legacyResult.RoleDetailList {
			legacyRoleARNs[r.Arn] = true
		}
		newRoleARNs := make(map[string]bool)
		for _, r := range result.RoleDetailList {
			newRoleARNs[r.Arn] = true
		}
		assert.Equal(t, legacyRoleARNs, newRoleARNs, "role ARNs should match")

		// Compare managed policies by ARN
		legacyPolicyARNs := make(map[string]bool)
		for _, p := range legacyResult.Policies {
			legacyPolicyARNs[p.Arn] = true
		}
		newPolicyARNs := make(map[string]bool)
		for _, p := range result.Policies {
			newPolicyARNs[p.Arn] = true
		}
		assert.Equal(t, legacyPolicyARNs, newPolicyARNs, "managed policy ARNs should match")
	})
}
