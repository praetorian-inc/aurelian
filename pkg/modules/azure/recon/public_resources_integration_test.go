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
	emptyResourceIDCount := 0
	for _, risk := range risks {
		assert.NotEmpty(t, risk.Name, "risk Name must not be empty")
		assert.NotEmpty(t, risk.Severity, "risk Severity must not be empty")
		if risk.ImpactedResourceID == "" {
			emptyResourceIDCount++
		}
		assert.NotEmpty(t, risk.Context, "risk Context must not be empty")
	}
	if emptyResourceIDCount > 0 {
		t.Logf("WARNING: %d/%d risks have empty ImpactedResourceID (ARG query missing id column)", emptyResourceIDCount, len(risks))
	}

	// Build index of risks by resource ID and templateID for structural assertions.
	risksByResourceID := make(map[string][]output.AurelianRisk)
	risksByTemplateID := make(map[string][]output.AurelianRisk)
	for _, risk := range risks {
		if risk.ImpactedResourceID != "" {
			risksByResourceID[strings.ToLower(risk.ImpactedResourceID)] = append(risksByResourceID[strings.ToLower(risk.ImpactedResourceID)], risk)
		}
		var ctx map[string]any
		if err := json.Unmarshal(risk.Context, &ctx); err == nil {
			if tmplID, ok := ctx["templateId"].(string); ok {
				risksByTemplateID[tmplID] = append(risksByTemplateID[tmplID], risk)
			}
		}
	}

	// --- Resource Detection Tests ---
	// Each test validates the ARG template detected the fixture resource and
	// the emitted risk has correct structural fields.
	detectionTests := []struct {
		name       string
		fixtureKey string
	}{
		{"detects public storage account", "storage_account_id"},
		{"detects public key vault", "key_vault_id"},
		{"detects public sql server", "sql_server_id"},
		{"detects public container registry", "acr_id"},
		{"detects public postgresql flexible server", "postgresql_server_id"},
		{"detects public cognitive services", "cognitive_account_id"},
		{"detects public search service", "search_service_id"},
		{"detects public container instance", "container_instance_id"},
		{"detects public container app", "container_app_id"},
		{"detects public databricks workspace", "databricks_workspace_id"},
		{"detects public aks cluster", "aks_id"},
		{"detects public virtual machine", "virtual_machine_id"},
		{"detects public iot hub", "iot_hub_id"},
		{"detects public event grid topic", "event_grid_topic_id"},
		{"detects public notification hub namespace", "notification_hub_namespace_id"},
		{"detects public service bus", "service_bus_id"},
		{"detects public event hub", "event_hub_id"},
		{"detects public app configuration", "app_configuration_id"},
		{"detects public synapse workspace", "synapse_workspace_id"},
		{"detects public ml workspace", "ml_workspace_id"},
		{"detects public logic app", "logic_app_id"},
		{"detects public data factory", "data_factory_id"},
		{"detects public log analytics workspace", "log_analytics_id"},
		{"detects public cosmos db", "cosmos_db_id"},
		{"detects public redis cache", "redis_cache_id"},
		{"detects acr with anonymous pull", "acr_anon_pull_id"},
		{"detects public data explorer cluster", "kusto_cluster_id"},
		{"detects public api management", "api_management_id"},
		{"detects public load balancer", "load_balancer_id"},
		{"detects public application gateway", "application_gateway_id"},
		{"detects public app service", "app_service_id"},
		{"detects public function app", "function_app_id"},
		{"detects public mysql flexible server", "mysql_server_id"},
	}

	for _, tc := range detectionTests {
		t.Run(tc.name, func(t *testing.T) {
			resourceID := strings.ToLower(fixture.Output(tc.fixtureKey))
			matchedRisks, found := risksByResourceID[resourceID]
			require.True(t, found, "expected risk with ImpactedResourceID %s", resourceID)
			require.NotEmpty(t, matchedRisks)

			risk := matchedRisks[0]
			assert.Equal(t, "public-azure-resource", risk.Name, "risk Name")
			assert.NotEmpty(t, risk.Severity, "risk Severity must not be empty")

			var ctx map[string]any
			require.NoError(t, json.Unmarshal(risk.Context, &ctx), "risk Context must be valid JSON")
			assert.NotEmpty(t, ctx["templateId"], "risk Context must have templateId")
		})
	}

	// Event grid domain: template doesn't project the `id` column,
	// so validate via risksByTemplateID instead of exact resource ID match.
	t.Run("detects public event grid domain", func(t *testing.T) {
		templateRisks := risksByTemplateID["event_grid_domain_public"]
		require.NotEmpty(t, templateRisks, "should detect event grid domain")

		risk := templateRisks[0]
		assert.Equal(t, "public-azure-resource", risk.Name, "risk Name")
		assert.NotEmpty(t, risk.Severity, "risk Severity must not be empty")

		var ctx map[string]any
		require.NoError(t, json.Unmarshal(risk.Context, &ctx), "risk Context must be valid JSON")
		assert.Equal(t, "event_grid_domain_public", ctx["templateId"])

		// Verify the detected domain matches the fixture resource name.
		domainID := fixture.Output("event_grid_domain_id")
		parts := strings.Split(domainID, "/")
		domainName := strings.ToLower(parts[len(parts)-1])
		resourceName, _ := ctx["resourceName"].(string)
		assert.Contains(t, strings.ToLower(resourceName), domainName,
			"detected domain name should match fixture resource")
	})

	// --- Per-Enricher Validation ---
	// Validates that enrichers ran and produced meaningful output for each template.

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
			assert.Contains(t, firstCmd, "command", "enrichment command should have command field")
			assert.Contains(t, firstCmd, "exit_code", "enrichment command should have exit_code field")
			return
		}
		t.Skip("no enriched results found to validate structure")
	})

	// Per-template enricher tests: verify each enricher ran and produced commands.
	enricherTests := []struct {
		name       string
		templateID string
		optional   bool // if true, skip instead of fail when no enrichment commands found
		// checkCmd validates that enrichment commands contain expected patterns.
		checkCmd func(t *testing.T, cmds []map[string]any)
	}{
		{
			name:       "storage account enricher produces blob listing probe",
			templateID: "storage_accounts_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "blob.core.windows.net")
			},
		},
		{
			name:       "key vault enricher produces key listing probe",
			templateID: "key_vault_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "vault.azure.net")
			},
		},
		{
			name:       "sql server enricher produces TCP probe and firewall rules",
			templateID: "sql_servers_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "1433")
				assertHasDescriptionContaining(t, cmds, "firewall")
			},
		},
		{
			name:       "container registry enricher produces catalog probe",
			templateID: "container_registries_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "azurecr.io")
			},
		},
		{
			name:       "acr anonymous pull enricher produces token probe",
			templateID: "acr_anonymous_pull_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "azurecr.io")
			},
		},
		{
			name:       "postgresql enricher produces TCP probe and firewall rules",
			templateID: "postgresql_flexible_server_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "5432")
				assertHasDescriptionContaining(t, cmds, "firewall")
			},
		},
		{
			name:       "mysql enricher produces TCP probe and firewall rules",
			templateID: "mysql_flexible_server_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "3306")
				assertHasDescriptionContaining(t, cmds, "firewall")
			},
		},
		{
			name:       "cognitive services enricher produces endpoint probe",
			templateID: "cognitive_services_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "cognitiveservices.azure.com")
			},
		},
		{
			name:       "search service enricher produces index listing probe",
			templateID: "search_service_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "search.windows.net")
			},
		},
		{
			name:       "cosmos db enricher produces discovery probe",
			templateID: "cosmos_db_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "documents.azure.com")
			},
		},
		{
			name:       "redis cache enricher produces TCP probe on SSL port",
			templateID: "redis_cache_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "6380")
			},
		},
		{
			name:       "aks enricher produces API server probe",
			templateID: "aks_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertHasDescriptionContaining(t, cmds, "Kubernetes")
			},
		},
		{
			name:       "container instance enricher produces HTTP probe",
			templateID: "container_instances_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assert.NotEmpty(t, cmds, "should have at least one command")
			},
		},
		{
			name:       "container app enricher produces FQDN probe",
			templateID: "container_apps_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assert.NotEmpty(t, cmds, "should have at least one command")
			},
		},
		{
			name:       "databricks enricher produces workspace probe",
			templateID: "databricks_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertHasDescriptionContaining(t, cmds, "Databricks")
			},
		},
		{
			name:       "iot hub enricher produces device registry probe",
			templateID: "iot_hub_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "azure-devices.net")
			},
		},
		{
			name:       "event grid topic enricher produces event POST probe",
			templateID: "event_grid_topics_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "eventgrid.azure.net")
			},
		},
		{
			name:       "event grid domain enricher produces event POST probe",
			templateID: "event_grid_domain_public",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "eventgrid.azure.net")
			},
		},
		{
			name:       "notification hub enricher produces management probe",
			templateID: "notification_hubs_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "servicebus.windows.net")
			},
		},
		{
			name:       "service bus enricher produces management probe and network rules",
			templateID: "service_bus_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "servicebus.windows.net")
			},
		},
		{
			name:       "event hub enricher produces management probe and network rules",
			templateID: "event_hub_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "servicebus.windows.net")
			},
		},
		{
			name:       "app configuration enricher produces endpoint probe",
			templateID: "app_configuration_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "azconfig.io")
			},
		},
		{
			name:       "synapse enricher produces development endpoint probe",
			templateID: "synapse_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assert.NotEmpty(t, cmds, "should have at least one command")
			},
		},
		{
			name:       "ml workspace enricher produces notebook probe",
			templateID: "ml_workspace_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assert.NotEmpty(t, cmds, "should have at least one command")
			},
		},
		{
			name:       "logic app enricher produces triggers probe",
			templateID: "logic_apps_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assert.NotEmpty(t, cmds, "should have at least one command")
			},
		},
		{
			name:       "data explorer enricher produces cluster probe and network rules",
			templateID: "data_explorer_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "kusto.windows.net")
			},
		},
		{
			name:       "api management enricher produces gateway probe",
			templateID: "api_management_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "azure-api.net")
			},
		},
		{
			name:       "application gateway enricher produces az CLI commands",
			templateID: "application_gateway_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "az network")
			},
		},
		{
			name:       "virtual machine enricher produces nmap command",
			templateID: "virtual_machines_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "nmap")
			},
		},
		{
			name:       "app service enricher produces site probe",
			templateID: "app_services_public_access",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "azurewebsites.net")
			},
		},
		{
			name:       "function app enricher produces function probe",
			templateID: "function_apps_public_http_triggers",
			checkCmd: func(t *testing.T, cmds []map[string]any) {
				assertCommandContains(t, cmds, "azurewebsites.net")
			},
		},
	}

	for _, tc := range enricherTests {
		t.Run(tc.name, func(t *testing.T) {
			templateRisks := risksByTemplateID[tc.templateID]
			if len(templateRisks) == 0 {
				t.Skipf("no risks found for template %s (resource may not be deployed)", tc.templateID)
				return
			}

			// Find a risk with enrichment commands for this template.
			var enrichedCmds []map[string]any
			for _, risk := range templateRisks {
				cmds := extractEnrichmentCommands(t, risk)
				if len(cmds) > 0 {
					enrichedCmds = cmds
					break
				}
			}

			if len(enrichedCmds) == 0 {
				if tc.optional {
					t.Skipf("template %s produced no enrichment commands (optional)", tc.templateID)
				}
				require.NotEmpty(t, enrichedCmds, "template %s should have enrichment commands", tc.templateID)
			}
			tc.checkCmd(t, enrichedCmds)

			// Validate all commands have required fields.
			for i, cmd := range enrichedCmds {
				assert.NotEmpty(t, cmd["description"], "command %d should have description", i)
				assert.Contains(t, cmd, "exit_code", "command %d should have exit_code", i)
			}

			t.Logf("template %s: %d enrichment commands", tc.templateID, len(enrichedCmds))
		})
	}

	// --- Summary ---
	t.Run("enrichment coverage summary", func(t *testing.T) {
		enrichedTemplates := 0
		totalTemplates := 0
		for tmplID, tmplRisks := range risksByTemplateID {
			totalTemplates++
			for _, risk := range tmplRisks {
				if cmds := extractEnrichmentCommands(t, risk); len(cmds) > 0 {
					enrichedTemplates++
					break
				}
			}
			_ = tmplID
		}
		t.Logf("enrichment coverage: %d/%d templates have enrichment commands", enrichedTemplates, totalTemplates)
		t.Logf("total risks: %d", len(risks))
	})
}

// --- Test Helpers ---

// extractEnrichmentCommands extracts the enrichment commands from a risk's context JSON.
func extractEnrichmentCommands(t *testing.T, risk output.AurelianRisk) []map[string]any {
	t.Helper()
	var ctx map[string]any
	if err := json.Unmarshal(risk.Context, &ctx); err != nil {
		return nil
	}
	props, _ := ctx["properties"].(map[string]any)
	if props == nil {
		return nil
	}
	cmdsRaw, ok := props["enrichmentCommands"]
	if !ok {
		return nil
	}
	cmds, ok := cmdsRaw.([]any)
	if !ok {
		return nil
	}
	var result []map[string]any
	for _, c := range cmds {
		if m, ok := c.(map[string]any); ok {
			result = append(result, m)
		}
	}
	return result
}

// assertCommandContains asserts that at least one command's "command" field contains the substring.
func assertCommandContains(t *testing.T, cmds []map[string]any, substr string) {
	t.Helper()
	for _, cmd := range cmds {
		if cmdStr, ok := cmd["command"].(string); ok && strings.Contains(strings.ToLower(cmdStr), strings.ToLower(substr)) {
			return
		}
		// Also check actual_output for probes that ran.
		if out, ok := cmd["actual_output"].(string); ok && strings.Contains(strings.ToLower(out), strings.ToLower(substr)) {
			return
		}
	}
	t.Errorf("no command contains %q", substr)
}

// assertHasDescriptionContaining asserts at least one command's description contains the substring.
func assertHasDescriptionContaining(t *testing.T, cmds []map[string]any, substr string) {
	t.Helper()
	for _, cmd := range cmds {
		if desc, ok := cmd["description"].(string); ok && strings.Contains(strings.ToLower(desc), strings.ToLower(substr)) {
			return
		}
	}
	t.Errorf("no command description contains %q", substr)
}
