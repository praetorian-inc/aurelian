//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/require"
)

// TestAzureListAllResourceEnumeration provisions Azure resources via Terraform,
// runs the azure/recon/list-all module, and asserts every provisioned resource
// appears in the results.
func TestAzureListAllResourceEnumeration(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/list-all")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "list-all")
	if !ok {
		t.Fatal("azure list-all module not registered")
	}

	subscriptionID := fixture.Output("subscription_id")

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"subscription-ids": []string{subscriptionID},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 1)

	t.Run("discovers resource groups", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("resource_group_id"))
		testutil.AssertResultContainsString(t, results, fixture.Output("func_resource_group_id"))
	})

	t.Run("discovers virtual network", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("vnet_id"))
	})

	t.Run("discovers network security group", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("nsg_id"))
	})

	t.Run("discovers storage accounts", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("storage_account_id"))
		testutil.AssertResultContainsString(t, results, fixture.Output("func_storage_account_id"))
	})

	t.Run("discovers key vault", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("key_vault_id"))
	})

	t.Run("discovers log analytics workspace", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("log_analytics_id"))
	})

	t.Run("discovers container registry", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("acr_id"))
	})

	t.Run("discovers data factory", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("data_factory_id"))
	})

	t.Run("discovers event grid topic", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("event_grid_topic_id"))
	})

	t.Run("discovers service bus namespace", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("service_bus_id"))
	})

	t.Run("discovers app service plans", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("service_plan_id"))
		testutil.AssertResultContainsString(t, results, fixture.Output("func_service_plan_id"))
	})

	t.Run("discovers web app", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("web_app_id"))
	})

	t.Run("discovers function app", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("function_app_id"))
	})

	t.Run("discovers automation account", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("automation_account_id"))
	})

	t.Run("discovers sql server", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("sql_server_id"))
	})

	t.Run("discovers network interface", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("nic_id"))
	})

	t.Run("discovers virtual machine", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("vm_id"))
	})
}
