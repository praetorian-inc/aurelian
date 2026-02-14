//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSAccountAuthDetails(t *testing.T) {
	fixture := NewFixture(t, "aws/gaad")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "account-auth-details")
	if !ok {
		t.Fatal("account-auth-details module not registered")
	}

	results, err := mod.Run(plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	})
	require.NoError(t, err)
	AssertMinResults(t, results, 1)

	// Parse the GAAD data from results
	raw, err := json.Marshal(results[0].Data)
	require.NoError(t, err)
	var gaad types.Gaad
	require.NoError(t, json.Unmarshal(raw, &gaad))

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
		for _, user := range gaad.UserDetailList {
			if user.UserName == userName {
				found = true
				assert.Equal(t, userArn, user.Arn)
				assert.Contains(t, user.GroupList, groupName)
				break
			}
		}
		assert.True(t, found, "expected user %s in UserDetailList", userName)
	})

	t.Run("contains test role", func(t *testing.T) {
		var found bool
		for _, role := range gaad.RoleDetailList {
			if role.RoleName == roleName {
				found = true
				assert.Equal(t, roleArn, role.Arn)
				break
			}
		}
		assert.True(t, found, "expected role %s in RoleDetailList", roleName)
	})

	t.Run("contains test group", func(t *testing.T) {
		var found bool
		for _, group := range gaad.GroupDetailList {
			if group.GroupName == groupName {
				found = true
				assert.Equal(t, groupArn, group.Arn)
				break
			}
		}
		assert.True(t, found, "expected group %s in GroupDetailList", groupName)
	})

	t.Run("contains test policy", func(t *testing.T) {
		var found bool
		for _, policy := range gaad.Policies {
			if policy.PolicyName == policyName {
				found = true
				assert.Equal(t, policyArn, policy.Arn)
				assert.True(t, policy.IsAttachable)
				// Verify policy has version list with a default version
				doc := policy.DefaultPolicyDocument()
				assert.NotNil(t, doc, "expected default policy document")
				break
			}
		}
		assert.True(t, found, "expected policy %s in Policies", policyName)
	})

	// Verify the raw results also contain our test resources via generic assertions
	AssertResultContainsString(t, results, userName)
	AssertResultContainsString(t, results, roleName)
	AssertResultContainsString(t, results, groupName)
	AssertResultContainsString(t, results, policyName)
}
