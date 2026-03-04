//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSAccountAuthDetails(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/graph")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "account-auth-details")
	if !ok {
		t.Fatal("account-auth-details module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)
	require.Len(t, results, 1, "account-auth-details module should output exactly 1 model")

	details, ok := results[0].(*types.AuthorizationAccountDetails)
	require.True(t, ok, "output should be *types.AuthorizationAccountDetails, got %T", results[0])

	// Fixture outputs.
	userNames := fixture.OutputList("user_names")
	userARNs := fixture.OutputList("user_arns")
	groupName := fixture.Output("group_name")
	lambdaRoleName := fixture.Output("lambda_role_name")
	assumableRoleName := fixture.Output("assumable_role_name")
	customPolicyARN := fixture.Output("custom_policy_arn")

	t.Run("account ID is populated", func(t *testing.T) {
		assert.NotEmpty(t, details.AccountID)
	})

	t.Run("fixture users present", func(t *testing.T) {
		foundNames := make(map[string]bool)
		foundARNs := make(map[string]bool)
		details.Users.Range(func(_ string, u types.UserDetail) bool {
			foundNames[u.UserName] = true
			foundARNs[u.Arn] = true
			return true
		})

		for _, name := range userNames {
			assert.True(t, foundNames[name], "GAAD should contain user %s", name)
		}
		for _, arn := range userARNs {
			assert.True(t, foundARNs[arn], "GAAD should contain user ARN %s", arn)
		}
	})

	t.Run("fixture group present", func(t *testing.T) {
		foundGroups := make(map[string]bool)
		details.Groups.Range(func(_ string, g types.GroupDetail) bool {
			foundGroups[g.GroupName] = true
			return true
		})
		assert.True(t, foundGroups[groupName], "GAAD should contain group %s", groupName)
	})

	t.Run("fixture roles present", func(t *testing.T) {
		foundRoles := make(map[string]bool)
		details.Roles.Range(func(_ string, r types.RoleDetail) bool {
			foundRoles[r.RoleName] = true
			return true
		})
		assert.True(t, foundRoles[lambdaRoleName], "GAAD should contain role %s", lambdaRoleName)
		assert.True(t, foundRoles[assumableRoleName], "GAAD should contain role %s", assumableRoleName)
	})

	t.Run("fixture managed policy present", func(t *testing.T) {
		foundPolicies := make(map[string]bool)
		details.Policies.Range(func(_ string, p types.ManagedPolicyDetail) bool {
			foundPolicies[p.Arn] = true
			return true
		})
		assert.True(t, foundPolicies[customPolicyARN], "GAAD should contain policy %s", customPolicyARN)
	})

	t.Run("non-trivial entity counts", func(t *testing.T) {
		assert.GreaterOrEqual(t, details.Users.Len(), len(userNames),
			"should have at least as many users as the fixture creates")
		assert.GreaterOrEqual(t, details.Roles.Len(), 2,
			"should have at least the 2 fixture roles")
		assert.GreaterOrEqual(t, details.Groups.Len(), 1,
			"should have at least the fixture group")
		assert.GreaterOrEqual(t, details.Policies.Len(), 1,
			"should have at least the fixture managed policy")
	})

	t.Run("diagnostic summary", func(t *testing.T) {
		t.Logf("=== Account Auth Details Summary ===")
		t.Logf("Account ID: %s", details.AccountID)
		t.Logf("Users:    %d", details.Users.Len())
		t.Logf("Roles:    %d", details.Roles.Len())
		t.Logf("Groups:   %d", details.Groups.Len())
		t.Logf("Policies: %d", details.Policies.Len())
	})
}
