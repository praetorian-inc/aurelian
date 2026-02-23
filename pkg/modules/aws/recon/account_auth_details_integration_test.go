//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSAccountAuthDetails(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/graph")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "account-auth-details")
	if !ok {
		t.Fatal("account-auth-details module not registered in plugin system")
	}

	results, err := mod.Run(plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	})
	require.NoError(t, err)
	require.Len(t, results, 1, "account-auth-details module should return exactly 1 result")

	result := results[0]
	details, ok := result.Data.(*types.AuthorizationAccountDetails)
	require.True(t, ok, "result data should be *types.AuthorizationAccountDetails, got %T", result.Data)

	// Fixture outputs.
	userNames := fixture.OutputList("user_names")
	userARNs := fixture.OutputList("user_arns")
	groupName := fixture.Output("group_name")
	lambdaRoleName := fixture.Output("lambda_role_name")
	assumableRoleName := fixture.Output("assumable_role_name")
	customPolicyARN := fixture.Output("custom_policy_arn")

	t.Run("result metadata is correct", func(t *testing.T) {
		assert.Equal(t, "account-auth-details", result.Metadata["module"])
		assert.Equal(t, plugin.PlatformAWS, result.Metadata["platform"])
		assert.Equal(t, "us-east-1", result.Metadata["region"])
		assert.NotEmpty(t, result.Metadata["accountID"])
		assert.Equal(t, details.AccountID, result.Metadata["accountID"])
	})

	t.Run("account ID is populated", func(t *testing.T) {
		assert.NotEmpty(t, details.AccountID)
	})

	t.Run("fixture users present", func(t *testing.T) {
		foundNames := make(map[string]bool)
		foundARNs := make(map[string]bool)
		for _, u := range details.UserDetailList {
			foundNames[u.UserName] = true
			foundARNs[u.Arn] = true
		}

		for _, name := range userNames {
			assert.True(t, foundNames[name], "GAAD should contain user %s", name)
		}
		for _, arn := range userARNs {
			assert.True(t, foundARNs[arn], "GAAD should contain user ARN %s", arn)
		}
	})

	t.Run("fixture group present", func(t *testing.T) {
		foundGroups := make(map[string]bool)
		for _, g := range details.GroupDetailList {
			foundGroups[g.GroupName] = true
		}
		assert.True(t, foundGroups[groupName], "GAAD should contain group %s", groupName)
	})

	t.Run("fixture roles present", func(t *testing.T) {
		foundRoles := make(map[string]bool)
		for _, r := range details.RoleDetailList {
			foundRoles[r.RoleName] = true
		}
		assert.True(t, foundRoles[lambdaRoleName], "GAAD should contain role %s", lambdaRoleName)
		assert.True(t, foundRoles[assumableRoleName], "GAAD should contain role %s", assumableRoleName)
	})

	t.Run("fixture managed policy present", func(t *testing.T) {
		foundPolicies := make(map[string]bool)
		for _, p := range details.Policies {
			foundPolicies[p.Arn] = true
		}
		assert.True(t, foundPolicies[customPolicyARN], "GAAD should contain policy %s", customPolicyARN)
	})

	t.Run("non-trivial entity counts", func(t *testing.T) {
		assert.GreaterOrEqual(t, len(details.UserDetailList), len(userNames),
			"should have at least as many users as the fixture creates")
		assert.GreaterOrEqual(t, len(details.RoleDetailList), 2,
			"should have at least the 2 fixture roles")
		assert.GreaterOrEqual(t, len(details.GroupDetailList), 1,
			"should have at least the fixture group")
		assert.GreaterOrEqual(t, len(details.Policies), 1,
			"should have at least the fixture managed policy")
	})

	t.Run("diagnostic summary", func(t *testing.T) {
		t.Logf("=== Account Auth Details Summary ===")
		t.Logf("Account ID: %s", details.AccountID)
		t.Logf("Users:    %d", len(details.UserDetailList))
		t.Logf("Roles:    %d", len(details.RoleDetailList))
		t.Logf("Groups:   %d", len(details.GroupDetailList))
		t.Logf("Policies: %d", len(details.Policies))
	})
}
