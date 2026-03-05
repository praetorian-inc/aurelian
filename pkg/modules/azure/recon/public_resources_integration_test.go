//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzurePublicResources(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/public-resources")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("azure public-resources module not registered in plugin system")
	}

	subscriptionID := fixture.Output("subscription_id")

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"subscription-id": []string{subscriptionID},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 1)

	// Collect risks from results.
	var risks []output.AurelianRisk
	for _, r := range results {
		if risk, ok := r.(output.AurelianRisk); ok {
			risks = append(risks, risk)
		}
	}
	require.NotEmpty(t, risks, "should emit at least one risk")

	// Validate risk fields on all results.
	for _, risk := range risks {
		assert.NotEmpty(t, risk.Name, "risk Name must not be empty")
		assert.NotEmpty(t, risk.Severity, "risk Severity must not be empty")
		assert.NotEmpty(t, risk.ImpactedARN, "risk ImpactedARN must not be empty")
		assert.NotEmpty(t, risk.Context, "risk Context must not be empty")
	}

	// ===== TIER 5A: Storage, Key Vault, App Service, Data Factory, Log Analytics, ACR =====
	t.Run("tier5a/detects public storage account", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("storage_account_public_id"))
	})
	t.Run("tier5a/detects public key vault", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("key_vault_public_id"))
	})
	t.Run("tier5a/detects public app service", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("app_service_public_id"))
	})
	t.Run("tier5a/detects public data factory", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("data_factory_public_id"))
	})
	t.Run("tier5a/detects public log analytics", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("log_analytics_public_id"))
	})
	t.Run("tier5a/detects public container registry", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("container_registry_public_id"))
	})

	// ===== TIER 5B: SQL Server, Cosmos DB, Service Bus, Event Hub, Redis, ACR Anon Pull =====
	t.Run("tier5b/detects public sql server", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("sql_server_public_id"))
	})
	t.Run("tier5b/detects public cosmos db", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("cosmos_db_public_id"))
	})
	t.Run("tier5b/detects public service bus", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("service_bus_public_id"))
	})
	t.Run("tier5b/detects public event hub", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("event_hub_public_id"))
	})
	t.Run("tier5b/detects public redis cache", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("redis_cache_public_id"))
	})

	// ===== TIER 5C: AKS, API Management, Load Balancer, VM =====
	t.Run("tier5c/detects public aks", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("aks_public_id"))
	})
	t.Run("tier5c/detects public api management", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("api_management_public_id"))
	})
	t.Run("tier5c/detects public load balancer", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("load_balancer_public_id"))
	})
	t.Run("tier5c/detects public virtual machine", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("virtual_machine_public_id"))
	})

	// ===== TIER 1: MySQL, PostgreSQL =====
	t.Run("tier1/detects public mysql", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("mysql_public_id"))
	})
	t.Run("tier1/detects public postgresql", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("postgresql_public_id"))
	})

	// ===== TIER 2: Cognitive Services, Search, Function App =====
	t.Run("tier2/detects public cognitive services", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("cognitive_services_public_id"))
	})
	t.Run("tier2/detects public search service", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("search_service_public_id"))
	})
	t.Run("tier2/detects public function app", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("function_app_public_id"))
	})

	// ===== TIER 3: IoT Hub, Event Grid, Notification Hub =====
	t.Run("tier3/detects public iot hub", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("iot_hub_public_id"))
	})
	t.Run("tier3/detects public event grid topic", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("event_grid_topic_public_id"))
	})
	t.Run("tier3/detects public notification hub", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("notification_hub_public_id"))
	})

	// ===== TIER 4A: App Config, Data Explorer, Container Instance, Databricks =====
	t.Run("tier4a/detects public app configuration", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("app_configuration_public_id"))
	})
	t.Run("tier4a/detects public data explorer", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("data_explorer_public_id"))
	})
	t.Run("tier4a/detects public container instance", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("container_instance_public_id"))
	})
	t.Run("tier4a/detects public databricks", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("databricks_public_id"))
	})

	// ===== TIER 4B: Synapse, ML Workspace =====
	t.Run("tier4b/detects public synapse", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("synapse_public_id"))
	})
	t.Run("tier4b/detects public ml workspace", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("ml_workspace_public_id"))
	})

	// ===== TIER 4C: Container App, Logic App, Application Gateway =====
	t.Run("tier4c/detects public container app", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("container_app_public_id"))
	})
	t.Run("tier4c/detects public logic app", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("logic_app_public_id"))
	})
	t.Run("tier4c/detects public application gateway", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("application_gateway_public_id"))
	})
}
