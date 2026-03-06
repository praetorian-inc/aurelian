//go:build integration

package recon

import (
	"context"
	"encoding/json"
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
			"subscription-ids": []string{subscriptionID},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 17)

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
		assert.NotEmpty(t, risk.ImpactedResourceID, "risk ImpactedResourceID must not be empty")
		assert.NotEmpty(t, risk.Context, "risk Context must not be empty")
	}

	// --- Original resources (Tier 5A/5B equivalents) ---

	t.Run("detects public storage account", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("storage_account_id"))
	})

	t.Run("detects public key vault", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("key_vault_id"))
	})

	t.Run("detects public sql server", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("sql_server_id"))
	})

	t.Run("detects public container registry", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("acr_id"))
	})

	// --- Database servers ---

	t.Run("detects public postgresql flexible server", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("postgresql_server_id"))
	})

	// --- AI and Search ---

	t.Run("detects public cognitive services", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("cognitive_account_id"))
	})

	t.Run("detects public search service", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("search_service_id"))
	})

	// --- Compute ---

	t.Run("detects public container instance", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("container_instance_id"))
	})

	t.Run("detects public container app", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("container_app_id"))
	})

	t.Run("detects public databricks workspace", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("databricks_workspace_id"))
	})

	t.Run("detects public aks cluster", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("aks_id"))
	})

	t.Run("detects public virtual machine", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("virtual_machine_id"))
	})

	// --- IoT and Messaging ---

	t.Run("detects public iot hub", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("iot_hub_id"))
	})

	t.Run("detects public event grid topic", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("event_grid_topic_id"))
	})

	t.Run("detects public notification hub namespace", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("notification_hub_namespace_id"))
	})

	t.Run("detects public service bus", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("service_bus_id"))
	})

	t.Run("detects public event hub", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("event_hub_id"))
	})

	// --- Configuration and Analytics ---

	t.Run("detects public app configuration", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("app_configuration_id"))
	})

	t.Run("detects public synapse workspace", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("synapse_workspace_id"))
	})

	t.Run("detects public ml workspace", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("ml_workspace_id"))
	})

	t.Run("detects public logic app", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("logic_app_id"))
	})

	t.Run("detects public data factory", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("data_factory_id"))
	})

	t.Run("detects public log analytics workspace", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("log_analytics_id"))
	})

	// --- Data stores ---

	t.Run("detects public cosmos db", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("cosmos_db_id"))
	})

	t.Run("detects public redis cache", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("redis_cache_id"))
	})

	t.Run("detects acr with anonymous pull", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("acr_anon_pull_id"))
	})

	t.Run("detects public data explorer cluster", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("kusto_cluster_id"))
	})

	// --- Networking ---

	t.Run("detects public api management", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("api_management_id"))
	})

	t.Run("detects public load balancer", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("load_balancer_id"))
	})

	t.Run("detects public application gateway", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("application_gateway_id"))
	})

	// --- Enrichment validation ---

	t.Run("enrichment commands present", func(t *testing.T) {
		enrichedCount := 0
		for _, risk := range risks {
			var ctx map[string]any
			if err := json.Unmarshal(risk.Context, &ctx); err != nil {
				continue
			}
			if props, ok := ctx["properties"].(map[string]any); ok {
				if _, hasCommands := props["enrichmentCommands"]; hasCommands {
					enrichedCount++
				}
			}
		}
		assert.Greater(t, enrichedCount, 0, "at least some results should have enrichment commands")
		t.Logf("enriched %d/%d risks", enrichedCount, len(risks))
	})

	t.Run("enrichment command structure valid", func(t *testing.T) {
		for _, risk := range risks {
			var ctx map[string]any
			if err := json.Unmarshal(risk.Context, &ctx); err != nil {
				continue
			}
			props, _ := ctx["properties"].(map[string]any)
			if props == nil {
				continue
			}
			cmdsRaw, ok := props["enrichmentCommands"]
			if !ok {
				continue
			}
			cmds, ok := cmdsRaw.([]any)
			if !ok || len(cmds) == 0 {
				continue
			}
			firstCmd, ok := cmds[0].(map[string]any)
			require.True(t, ok, "enrichment command should be a map")
			assert.NotEmpty(t, firstCmd["description"], "enrichment command should have description")
			return
		}
		t.Skip("no enriched results found to validate structure")
	})
}
