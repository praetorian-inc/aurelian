//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSAccountAuthDetails(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/gaad")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "account-auth-details")
	if !ok {
		t.Fatal("account-auth-details module not registered")
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
	testutil.AssertMinResults(t, results, 1)

	// The first result should be the GAAD data
	gaadPtr, ok := results[0].(*types.AuthorizationAccountDetails)
	require.True(t, ok, "expected *types.AuthorizationAccountDetails, got %T", results[0])
	gaad := *gaadPtr

	// Get expected names/ARNs from terraform outputs
	userName := fixture.Output("user_name")
	userArn := fixture.Output("user_arn")
	roleName := fixture.Output("role_name")
	roleArn := fixture.Output("role_arn")
	groupName := fixture.Output("group_name")
	groupArn := fixture.Output("group_arn")
	policyName := fixture.Output("policy_name")
	policyArn := fixture.Output("policy_arn")

	t.Run("contains test user", func(t *testing.T) {
		var found bool
		gaad.Users.Range(func(_ string, user types.UserDetail) bool {
			if user.UserName == userName {
				found = true
				assert.Equal(t, userArn, user.Arn)
				assert.Contains(t, user.GroupList, groupName)
				return false
			}
			return true
		})
		assert.True(t, found, "expected user %s in Users", userName)
	})

	t.Run("contains test role", func(t *testing.T) {
		var found bool
		gaad.Roles.Range(func(_ string, role types.RoleDetail) bool {
			if role.RoleName == roleName {
				found = true
				assert.Equal(t, roleArn, role.Arn)
				return false
			}
			return true
		})
		assert.True(t, found, "expected role %s in Roles", roleName)
	})

	t.Run("contains test group", func(t *testing.T) {
		var found bool
		gaad.Groups.Range(func(_ string, group types.GroupDetail) bool {
			if group.GroupName == groupName {
				found = true
				assert.Equal(t, groupArn, group.Arn)
				return false
			}
			return true
		})
		assert.True(t, found, "expected group %s in Groups", groupName)
	})

	t.Run("contains test policy", func(t *testing.T) {
		var found bool
		gaad.Policies.Range(func(_ string, policy types.ManagedPolicyDetail) bool {
			if policy.PolicyName == policyName {
				found = true
				assert.Equal(t, policyArn, policy.Arn)
				assert.True(t, policy.IsAttachable)
				doc := policy.DefaultPolicyDocument()
				assert.NotNil(t, doc, "expected default policy document")
				return false
			}
			return true
		})
		assert.True(t, found, "expected policy %s in Policies", policyName)
	})

	// Verify the raw results also contain our test resources via generic assertions
	testutil.AssertResultContainsString(t, results, userName)
	testutil.AssertResultContainsString(t, results, roleName)
	testutil.AssertResultContainsString(t, results, groupName)
	testutil.AssertResultContainsString(t, results, policyName)
}
