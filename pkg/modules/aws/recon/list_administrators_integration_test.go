//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListAdministratorsIntegration(t *testing.T) {
	// This fixture includes both admin and non-admin IAM principals so the test can
	// assert inclusion and exclusion behavior for list-administrators in one run.
	fixture := testutil.NewAWSFixture(t, "aws/recon/list-administrators")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-administrators")
	if !ok {
		t.Skip("list-administrators module not registered in plugin system")
	}

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"resource-type": []string{"AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::Group"},
			"scan-type":     "full",
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 1)

	t.Run("discovers admin user", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("admin_user_name"))
	})

	t.Run("discovers admin role", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("admin_role_name"))
	})

	t.Run("discovers admin group", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("admin_group_name"))
	})

	t.Run("discovers admin group member user", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("admin_group_member_user_name"))
	})

	t.Run("filters non-admin principals", func(t *testing.T) {
		assertResultDoesNotContainString(t, results, fixture.Output("non_admin_user_name"))
		assertResultDoesNotContainString(t, results, fixture.Output("non_admin_role_name"))
		assertResultDoesNotContainString(t, results, fixture.Output("non_admin_group_name"))
	})

	t.Run("all emitted principals are admin IAM entities", func(t *testing.T) {
		for _, result := range results {
			resource, ok := resultToAWSResource(result)
			require.True(t, ok, "expected output.AWSResource result, got %T", result)
			assert.True(t, resource.IsAdmin, "expected IsAdmin=true for %s %s", resource.ResourceType, resource.ResourceID)
			assert.Contains(t, []string{"AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::Group"}, resource.ResourceType)
		}
	})
}

func assertResultDoesNotContainString(t *testing.T, results []model.AurelianModel, unexpected string) {
	t.Helper()

	for _, result := range results {
		if containsPrincipalName(result, unexpected) {
			t.Fatalf("did not expect result containing %q", unexpected)
		}
	}
}

func containsPrincipalName(result model.AurelianModel, principalName string) bool {
	resource, ok := resultToAWSResource(result)
	if !ok {
		return false
	}

	if resource.ResourceID == principalName {
		return true
	}

	return resource.DisplayName == principalName
}

func resultToAWSResource(result model.AurelianModel) (output.AWSResource, bool) {
	resource, ok := result.(output.AWSResource)
	if ok {
		return resource, true
	}

	resourcePointer, ok := result.(*output.AWSResource)
	if !ok {
		return output.AWSResource{}, false
	}

	return *resourcePointer, true
}
