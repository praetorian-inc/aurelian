//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
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
	testutil.AssertMinResults(t, results, 20)

	// =====================================================================
	// Index risks by template ID for precise assertions.
	// =====================================================================

	type riskWithContext struct {
		Risk       output.AurelianRisk
		CtxMap     map[string]any
		Template   string
		ResourceID string
	}

	var all []riskWithContext
	byTemplate := make(map[string][]riskWithContext)
	for _, r := range results {
		risk, ok := r.(output.AurelianRisk)
		if !ok {
			continue
		}
		var ctx map[string]any
		require.NoError(t, json.Unmarshal(risk.Context, &ctx))
		tid, _ := ctx["templateId"].(string)
		rc := riskWithContext{
			Risk:       risk,
			CtxMap:     ctx,
			Template:   tid,
			ResourceID: risk.ImpactedResourceID,
		}
		all = append(all, rc)
		byTemplate[tid] = append(byTemplate[tid], rc)
	}

	// Helper: check if a fixture output exists and is non-empty.
	fixtureHasOutput := func(key string) bool {
		defer func() { recover() }() // Output() calls t.Fatalf on missing keys
		v := fixture.Output(key)
		return v != ""
	}

	// Helper: find a risk for a specific fixture resource within a template.
	findRisk := func(t *testing.T, templateID, fixtureResourceIDKey string) riskWithContext {
		t.Helper()
		expectedID := strings.ToLower(fixture.Output(fixtureResourceIDKey))
		require.NotEmpty(t, expectedID, "fixture output %q is empty", fixtureResourceIDKey)
		risks, ok := byTemplate[templateID]
		require.True(t, ok, "no findings for template %q", templateID)
		for _, rc := range risks {
			if strings.EqualFold(rc.ResourceID, expectedID) {
				return rc
			}
		}
		t.Fatalf("template %q has %d findings but none match fixture resource %q (%s)",
			templateID, len(risks), expectedID, fixtureResourceIDKey)
		return riskWithContext{} // unreachable
	}

	// Helper: assert a specific risk's common fields.
	// resourceNameSubstr is an environment-agnostic suffix (e.g., "-kv", "sa", "-aks")
	// that must appear in the ImpactedResourceID to confirm the right resource was caught.
	assertRisk := func(t *testing.T, rc riskWithContext, expectedTemplate string, expectedSeverity output.RiskSeverity, resourceNameSubstr string) {
		t.Helper()
		assert.Equal(t, "public-azure-resource", rc.Risk.Name)
		assert.Equal(t, expectedSeverity, rc.Risk.Severity,
			"template %s: expected severity %s, got %s", expectedTemplate, expectedSeverity, rc.Risk.Severity)
		assert.Equal(t, expectedTemplate, rc.Template)
		assert.NotEmpty(t, rc.Risk.ImpactedResourceID)
		assert.NotEmpty(t, rc.Risk.Context)
		assert.Contains(t, strings.ToLower(rc.Risk.ImpactedResourceID), strings.ToLower(resourceNameSubstr),
			"template %s: ImpactedResourceID %q should contain resource name substring %q",
			expectedTemplate, rc.Risk.ImpactedResourceID, resourceNameSubstr)
	}

	// =====================================================================
	// Storage & Data
	// =====================================================================

	t.Run("storage_accounts_public_access", func(t *testing.T) {
		rc := findRisk(t, "storage_accounts_public_access", "storage_account_id")
		assertRisk(t, rc, "storage_accounts_public_access", output.RiskSeverityHigh, "sa")
	})

	t.Run("key_vault_public_access", func(t *testing.T) {
		rc := findRisk(t, "key_vault_public_access", "key_vault_id")
		assertRisk(t, rc, "key_vault_public_access", output.RiskSeverityHigh, "-kv")
	})

	t.Run("cosmos_db_public_access", func(t *testing.T) {
		rc := findRisk(t, "cosmos_db_public_access", "cosmos_db_id")
		assertRisk(t, rc, "cosmos_db_public_access", output.RiskSeverityHigh, "-cosmos")
	})

	t.Run("redis_cache_public_access", func(t *testing.T) {
		rc := findRisk(t, "redis_cache_public_access", "redis_cache_id")
		assertRisk(t, rc, "redis_cache_public_access", output.RiskSeverityLow, "-redis")
	})

	t.Run("app_configuration_public_access", func(t *testing.T) {
		rc := findRisk(t, "app_configuration_public_access", "app_configuration_id")
		assertRisk(t, rc, "app_configuration_public_access", output.RiskSeverityMedium, "-appconf")
	})

	// =====================================================================
	// Databases
	// =====================================================================

	t.Run("sql_servers_public_access", func(t *testing.T) {
		if !fixtureHasOutput("sql_server_id") {
			t.Skip("sql_server not provisioned in this environment")
		}
		rc := findRisk(t, "sql_servers_public_access", "sql_server_id")
		assertRisk(t, rc, "sql_servers_public_access", output.RiskSeverityHigh, "-w-sql")
	})

	t.Run("postgresql_flexible_server_public_access", func(t *testing.T) {
		rc := findRisk(t, "postgresql_flexible_server_public_access", "postgresql_server_id")
		assertRisk(t, rc, "postgresql_flexible_server_public_access", output.RiskSeverityMedium, "-pg")
	})

	// =====================================================================
	// Container & Registry
	// =====================================================================

	t.Run("container_registries_public_access", func(t *testing.T) {
		rc := findRisk(t, "container_registries_public_access", "acr_id")
		assertRisk(t, rc, "container_registries_public_access", output.RiskSeverityHigh, "acr")
	})

	t.Run("acr_anonymous_pull_access", func(t *testing.T) {
		rc := findRisk(t, "acr_anonymous_pull_access", "acr_anon_pull_id")
		assertRisk(t, rc, "acr_anonymous_pull_access", output.RiskSeverityHigh, "acranon")
	})

	t.Run("container_apps_public_access", func(t *testing.T) {
		if !fixtureHasOutput("container_app_id") {
			t.Skip("container_app not provisioned in this environment")
		}
		rc := findRisk(t, "container_apps_public_access", "container_app_id")
		assertRisk(t, rc, "container_apps_public_access", output.RiskSeverityMedium, "-w-ca")
	})

	t.Run("container_instances_public_access", func(t *testing.T) {
		rc := findRisk(t, "container_instances_public_access", "container_instance_id")
		assertRisk(t, rc, "container_instances_public_access", output.RiskSeverityMedium, "-ci")
	})

	t.Run("aks_public_access", func(t *testing.T) {
		rc := findRisk(t, "aks_public_access", "aks_id")
		assertRisk(t, rc, "aks_public_access", output.RiskSeverityHigh, "-aks")
	})

	// =====================================================================
	// AI & Search
	// =====================================================================

	t.Run("cognitive_services_public_access", func(t *testing.T) {
		rc := findRisk(t, "cognitive_services_public_access", "cognitive_account_id")
		assertRisk(t, rc, "cognitive_services_public_access", output.RiskSeverityMedium, "-cog")
	})

	t.Run("search_service_public_access", func(t *testing.T) {
		rc := findRisk(t, "search_service_public_access", "search_service_id")
		assertRisk(t, rc, "search_service_public_access", output.RiskSeverityMedium, "-search")
	})

	// =====================================================================
	// Compute
	// =====================================================================

	t.Run("virtual_machines_public_access", func(t *testing.T) {
		rc := findRisk(t, "virtual_machines_public_access", "virtual_machine_id")
		assertRisk(t, rc, "virtual_machines_public_access", output.RiskSeverityHigh, "-vm")
	})

	t.Run("databricks_public_access", func(t *testing.T) {
		rc := findRisk(t, "databricks_public_access", "databricks_workspace_id")
		assertRisk(t, rc, "databricks_public_access", output.RiskSeverityMedium, "-dbw")
	})

	// =====================================================================
	// IoT & Messaging
	// =====================================================================

	t.Run("iot_hub_public_access", func(t *testing.T) {
		rc := findRisk(t, "iot_hub_public_access", "iot_hub_id")
		assertRisk(t, rc, "iot_hub_public_access", output.RiskSeverityMedium, "-iot")
	})

	t.Run("event_grid_topics_public_access", func(t *testing.T) {
		rc := findRisk(t, "event_grid_topics_public_access", "event_grid_topic_id")
		assertRisk(t, rc, "event_grid_topics_public_access", output.RiskSeverityMedium, "-egt")
	})

	t.Run("notification_hubs_public_access", func(t *testing.T) {
		rc := findRisk(t, "notification_hubs_public_access", "notification_hub_namespace_id")
		assertRisk(t, rc, "notification_hubs_public_access", output.RiskSeverityMedium, "-nhns")
	})

	t.Run("service_bus_public_access", func(t *testing.T) {
		rc := findRisk(t, "service_bus_public_access", "service_bus_id")
		assertRisk(t, rc, "service_bus_public_access", output.RiskSeverityLow, "-sbus")
	})

	t.Run("event_hub_public_access", func(t *testing.T) {
		rc := findRisk(t, "event_hub_public_access", "event_hub_id")
		assertRisk(t, rc, "event_hub_public_access", output.RiskSeverityHigh, "-eh")
	})

	// =====================================================================
	// Analytics & Integration
	// =====================================================================

	t.Run("synapse_public_access", func(t *testing.T) {
		if !fixtureHasOutput("synapse_workspace_id") {
			t.Skip("synapse_workspace not provisioned in this environment")
		}
		rc := findRisk(t, "synapse_public_access", "synapse_workspace_id")
		assertRisk(t, rc, "synapse_public_access", output.RiskSeverityMedium, "-w-syn")
	})

	t.Run("ml_workspace_public_access", func(t *testing.T) {
		if !fixtureHasOutput("ml_workspace_id") {
			t.Skip("ml_workspace not provisioned in this environment")
		}
		rc := findRisk(t, "ml_workspace_public_access", "ml_workspace_id")
		assertRisk(t, rc, "ml_workspace_public_access", output.RiskSeverityMedium, "-w-mlw")
	})

	t.Run("logic_apps_public_access", func(t *testing.T) {
		rc := findRisk(t, "logic_apps_public_access", "logic_app_id")
		assertRisk(t, rc, "logic_apps_public_access", output.RiskSeverityMedium, "-la")
	})

	t.Run("data_factory_public_access", func(t *testing.T) {
		rc := findRisk(t, "data_factory_public_access", "data_factory_id")
		assertRisk(t, rc, "data_factory_public_access", output.RiskSeverityLow, "-adf")
	})

	t.Run("log_analytics_public_access", func(t *testing.T) {
		rc := findRisk(t, "log_analytics_public_access", "log_analytics_id")
		assertRisk(t, rc, "log_analytics_public_access", output.RiskSeverityLow, "-law")
	})

	t.Run("data_explorer_public_access", func(t *testing.T) {
		rc := findRisk(t, "data_explorer_public_access", "kusto_cluster_id")
		assertRisk(t, rc, "data_explorer_public_access", output.RiskSeverityMedium, "kusto")
	})

	// =====================================================================
	// Networking
	// =====================================================================

	t.Run("api_management_public_access", func(t *testing.T) {
		rc := findRisk(t, "api_management_public_access", "api_management_id")
		assertRisk(t, rc, "api_management_public_access", output.RiskSeverityMedium, "-apim")
	})

	t.Run("load_balancers_public", func(t *testing.T) {
		rc := findRisk(t, "load_balancers_public", "load_balancer_id")
		assertRisk(t, rc, "load_balancers_public", output.RiskSeverityHigh, "-lb")
	})

	t.Run("application_gateway_public_access", func(t *testing.T) {
		rc := findRisk(t, "application_gateway_public_access", "application_gateway_id")
		assertRisk(t, rc, "application_gateway_public_access", output.RiskSeverityMedium, "-appgw")
	})

	// =====================================================================
	// Cross-finding invariants
	// =====================================================================

	t.Run("all risks have name public-azure-resource", func(t *testing.T) {
		for _, rc := range all {
			assert.Equal(t, "public-azure-resource", rc.Risk.Name,
				"template %q: risk name should be public-azure-resource", rc.Template)
		}
	})

	t.Run("all risks have valid severity", func(t *testing.T) {
		validSeverities := map[output.RiskSeverity]bool{
			output.RiskSeverityInfo: true, output.RiskSeverityLow: true,
			output.RiskSeverityMedium: true, output.RiskSeverityHigh: true,
			output.RiskSeverityCritical: true,
		}
		for _, rc := range all {
			assert.True(t, validSeverities[rc.Risk.Severity],
				"template %q: invalid severity %q", rc.Template, rc.Risk.Severity)
		}
	})

	t.Run("all risks have non-empty resource ID", func(t *testing.T) {
		for _, rc := range all {
			assert.NotEmpty(t, rc.Risk.ImpactedResourceID,
				"template %q: ImpactedResourceID must not be empty", rc.Template)
		}
	})

	t.Run("all risks have valid JSON context with templateId", func(t *testing.T) {
		for _, rc := range all {
			assert.NotEmpty(t, rc.Template,
				"risk context must contain templateId")
		}
	})

	t.Run("all risks have resourceId in context", func(t *testing.T) {
		for _, rc := range all {
			resID, _ := rc.CtxMap["resourceId"].(string)
			assert.NotEmpty(t, resID,
				"template %q: context should contain resourceId", rc.Template)
		}
	})

	t.Run("most risks have resourceType in context", func(t *testing.T) {
		withType := 0
		for _, rc := range all {
			resType, _ := rc.CtxMap["resourceType"].(string)
			if resType != "" {
				withType++
			}
		}
		// At least 80% of findings should have resourceType populated.
		ratio := float64(withType) / float64(len(all))
		assert.Greater(t, ratio, 0.8,
			"only %d/%d findings have resourceType in context", withType, len(all))
	})

	t.Run("no duplicate findings per resource per template", func(t *testing.T) {
		seen := make(map[string]int)
		for _, rc := range all {
			key := rc.Template + "|" + strings.ToLower(rc.ResourceID)
			seen[key]++
		}
		for key, count := range seen {
			assert.Equal(t, 1, count,
				"duplicate finding: %s appears %d times", key, count)
		}
	})

	t.Run("severity distribution has all expected levels", func(t *testing.T) {
		sevCounts := make(map[output.RiskSeverity]int)
		for _, rc := range all {
			sevCounts[rc.Risk.Severity]++
		}
		assert.Greater(t, sevCounts[output.RiskSeverityHigh], 0,
			"should have at least one high severity finding")
		assert.Greater(t, sevCounts[output.RiskSeverityMedium], 0,
			"should have at least one medium severity finding")
		assert.Greater(t, sevCounts[output.RiskSeverityLow], 0,
			"should have at least one low severity finding")
	})
}
