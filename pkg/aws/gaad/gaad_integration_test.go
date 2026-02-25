//go:build integration

package gaad

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
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
		result.Users.Range(func(_ string, u types.UserDetail) bool {
			foundUsers[u.UserName] = true
			return true
		})

		for _, name := range userNames {
			assert.True(t, foundUsers[name], "GAAD should contain user %s", name)
		}
	})

	t.Run("groups are collected", func(t *testing.T) {
		groupName := fixture.Output("group_name")

		foundGroups := make(map[string]bool)
		result.Groups.Range(func(_ string, g types.GroupDetail) bool {
			foundGroups[g.GroupName] = true
			return true
		})

		assert.True(t, foundGroups[groupName], "GAAD should contain group %s", groupName)
	})

	t.Run("roles are collected", func(t *testing.T) {
		lambdaRoleName := fixture.Output("lambda_role_name")
		assumableRoleName := fixture.Output("assumable_role_name")

		foundRoles := make(map[string]bool)
		result.Roles.Range(func(_ string, r types.RoleDetail) bool {
			foundRoles[r.RoleName] = true
			return true
		})

		assert.True(t, foundRoles[lambdaRoleName], "GAAD should contain role %s", lambdaRoleName)
		assert.True(t, foundRoles[assumableRoleName], "GAAD should contain role %s", assumableRoleName)
	})

	t.Run("managed policies are collected", func(t *testing.T) {
		customPolicyARN := fixture.Output("custom_policy_arn")

		foundPolicies := make(map[string]bool)
		result.Policies.Range(func(_ string, p types.ManagedPolicyDetail) bool {
			foundPolicies[p.Arn] = true
			return true
		})

		assert.True(t, foundPolicies[customPolicyARN], "GAAD should contain policy %s", customPolicyARN)
	})

	t.Run("inline policies are present on users", func(t *testing.T) {
		userNames := fixture.OutputList("user_names")

		var found bool
		result.Users.Range(func(_ string, u types.UserDetail) bool {
			if u.UserName == userNames[0] {
				assert.NotEmpty(t, u.UserPolicyList, "user %s should have inline policies", u.UserName)
				found = true
				return false
			}
			return true
		})
		if !found {
			t.Errorf("user %s not found in GAAD results", userNames[0])
		}
	})

	t.Run("group memberships are present", func(t *testing.T) {
		userNames := fixture.OutputList("user_names")
		groupName := fixture.Output("group_name")

		var found bool
		result.Users.Range(func(_ string, u types.UserDetail) bool {
			if u.UserName == userNames[0] {
				assert.Contains(t, u.GroupList, groupName, "user %s should be in group %s", u.UserName, groupName)
				found = true
				return false
			}
			return true
		})
		if !found {
			t.Errorf("user %s not found in GAAD results", userNames[0])
		}
	})

	t.Run("role trust policies are present", func(t *testing.T) {
		lambdaRoleName := fixture.Output("lambda_role_name")

		var found bool
		result.Roles.Range(func(_ string, r types.RoleDetail) bool {
			if r.RoleName == lambdaRoleName {
				assert.NotEmpty(t, r.AssumeRolePolicyDocument.Statement,
					"role %s should have a trust policy with statements", r.RoleName)
				found = true
				return false
			}
			return true
		})
		if !found {
			t.Errorf("role %s not found in GAAD results", lambdaRoleName)
		}
	})

	t.Run("managed policy versions are present", func(t *testing.T) {
		customPolicyARN := fixture.Output("custom_policy_arn")

		var found bool
		result.Policies.Range(func(_ string, p types.ManagedPolicyDetail) bool {
			if p.Arn == customPolicyARN {
				assert.NotEmpty(t, p.PolicyVersionList, "policy %s should have versions", p.Arn)
				doc := p.DefaultPolicyDocument()
				assert.NotNil(t, doc, "policy %s should have a default version document", p.Arn)
				found = true
				return false
			}
			return true
		})
		if !found {
			t.Errorf("policy %s not found in GAAD results", customPolicyARN)
		}
	})
}
