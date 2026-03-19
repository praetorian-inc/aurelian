package recon

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	publicresources "github.com/praetorian-inc/aurelian/pkg/templates/azure/public-resources"
)

func TestModuleMetadata(t *testing.T) {
	m := &AzurePublicResourcesModule{}

	assert.Equal(t, "public-resources", m.ID())
	assert.Equal(t, "Azure Public Resources", m.Name())
	assert.Equal(t, plugin.PlatformAzure, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())

	authors := m.Authors()
	require.Len(t, authors, 1)
	assert.Equal(t, "Praetorian", authors[0])

	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
	assert.Equal(t, []string{"Microsoft.Resources/subscriptions"}, m.SupportedResourceTypes())
}

func TestPublicResourcesParameters(t *testing.T) {
	m := &AzurePublicResourcesModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["subscription-ids"], "should have subscription-ids param")
	assert.True(t, paramNames["template-dir"], "should have template-dir param")
	assert.True(t, paramNames["output-dir"], "should have output-dir param")
}

func TestPublicResourcesTemplateLoader_LoadsAll36(t *testing.T) {
	loader, err := publicresources.NewLoader()
	require.NoError(t, err)

	tmps := loader.GetTemplates()
	assert.Len(t, tmps, 36, "should load exactly 36 public-resources templates")

	// Every known template ID must be present.
	expectedIDs := map[string]bool{
		"acr_anonymous_pull_access":                true,
		"aks_public_access":                        true,
		"api_management_public_access":             true,
		"apim_cross_tenant_signup_bypass":          true,
		"app_configuration_public_access":          true,
		"app_services_public_access":               true,
		"application_gateway_public_access":        true,
		"cognitive_services_public_access":          true,
		"container_apps_public_access":             true,
		"container_instances_public_access":        true,
		"container_registries_public_access":       true,
		"cosmos_db_public_access":                  true,
		"data_explorer_public_access":              true,
		"data_factory_public_access":               true,
		"databricks_public_access":                 true,
		"event_grid_domain_public":                 true,
		"event_grid_topics_public_access":          true,
		"event_hub_public_access":                  true,
		"function_apps_public_http_triggers":       true,
		"iot_hub_public_access":                    true,
		"key_vault_public_access":                  true,
		"load_balancers_public":                    true,
		"log_analytics_public_access":              true,
		"logic_apps_public_access":                 true,
		"ml_workspace_public_access":               true,
		"mysql_flexible_server_public_access":      true,
		"notification_hubs_public_access":          true,
		"openai_public_access":                     true,
		"postgresql_flexible_server_public_access": true,
		"redis_cache_public_access":                true,
		"search_service_public_access":             true,
		"service_bus_public_access":                true,
		"sql_servers_public_access":                true,
		"storage_accounts_public_access":           true,
		"synapse_public_access":                    true,
		"virtual_machines_public_access":           true,
	}

	foundIDs := make(map[string]bool)
	for _, tmpl := range tmps {
		assert.NotEmpty(t, tmpl.ID)
		assert.NotEmpty(t, tmpl.Name)
		assert.NotEmpty(t, tmpl.Query)
		assert.NotEmpty(t, tmpl.Severity, "template %s should have severity", tmpl.ID)
		foundIDs[tmpl.ID] = true
	}

	for id := range expectedIDs {
		assert.True(t, foundIDs[id], "missing template: %s", id)
	}

	// No extra unknown templates.
	for _, tmpl := range tmps {
		assert.True(t, expectedIDs[tmpl.ID], "unexpected template: %s", tmpl.ID)
	}
}

func TestPublicResourcesTemplateLoader_SeveritiesMatchExpected(t *testing.T) {
	loader, err := publicresources.NewLoader()
	require.NoError(t, err)

	expectedSeverities := map[string]output.RiskSeverity{
		"acr_anonymous_pull_access":                output.RiskSeverityHigh,
		"aks_public_access":                        output.RiskSeverityHigh,
		"api_management_public_access":             output.RiskSeverityMedium,
		"apim_cross_tenant_signup_bypass":          output.RiskSeverityMedium,
		"app_configuration_public_access":          output.RiskSeverityMedium,
		"app_services_public_access":               output.RiskSeverityMedium,
		"application_gateway_public_access":        output.RiskSeverityMedium,
		"cognitive_services_public_access":          output.RiskSeverityMedium,
		"container_apps_public_access":             output.RiskSeverityMedium,
		"container_instances_public_access":        output.RiskSeverityMedium,
		"container_registries_public_access":       output.RiskSeverityHigh,
		"cosmos_db_public_access":                  output.RiskSeverityHigh,
		"data_explorer_public_access":              output.RiskSeverityMedium,
		"data_factory_public_access":               output.RiskSeverityLow,
		"databricks_public_access":                 output.RiskSeverityMedium,
		"event_grid_domain_public":                 output.RiskSeverityHigh,
		"event_grid_topics_public_access":          output.RiskSeverityMedium,
		"event_hub_public_access":                  output.RiskSeverityHigh,
		"function_apps_public_http_triggers":       output.RiskSeverityMedium,
		"iot_hub_public_access":                    output.RiskSeverityMedium,
		"key_vault_public_access":                  output.RiskSeverityHigh,
		"load_balancers_public":                    output.RiskSeverityHigh,
		"log_analytics_public_access":              output.RiskSeverityLow,
		"logic_apps_public_access":                 output.RiskSeverityMedium,
		"ml_workspace_public_access":               output.RiskSeverityMedium,
		"mysql_flexible_server_public_access":      output.RiskSeverityMedium,
		"notification_hubs_public_access":          output.RiskSeverityMedium,
		"openai_public_access":                     output.RiskSeverityHigh,
		"postgresql_flexible_server_public_access": output.RiskSeverityMedium,
		"redis_cache_public_access":                output.RiskSeverityLow,
		"search_service_public_access":             output.RiskSeverityMedium,
		"service_bus_public_access":                output.RiskSeverityLow,
		"sql_servers_public_access":                output.RiskSeverityHigh,
		"storage_accounts_public_access":           output.RiskSeverityHigh,
		"synapse_public_access":                    output.RiskSeverityMedium,
		"virtual_machines_public_access":           output.RiskSeverityHigh,
	}

	for _, tmpl := range loader.GetTemplates() {
		expected, ok := expectedSeverities[tmpl.ID]
		require.True(t, ok, "no expected severity for template %s", tmpl.ID)
		assert.Equal(t, expected, output.NormalizeSeverity(tmpl.Severity),
			"template %s: severity mismatch", tmpl.ID)
	}
}

func TestPublicResourcesTemplateLoader_NoOverlapWithConfigurationScan(t *testing.T) {
	m := &AzurePublicResourcesModule{}
	require.NoError(t, m.initialize())
	assert.Len(t, m.templates, 36)

	for _, tmpl := range m.templates {
		// None of these should be configuration-scan templates.
		assert.NotContains(t, tmpl.ID, "auth_disabled",
			"public-resources template %s looks like a configuration-scan template", tmpl.ID)
		assert.NotContains(t, tmpl.ID, "remote_debugging",
			"public-resources template %s looks like a configuration-scan template", tmpl.ID)
		assert.NotContains(t, tmpl.ID, "privilege_escalation",
			"public-resources template %s looks like a configuration-scan template", tmpl.ID)
		assert.NotContains(t, tmpl.ID, "rbac_disabled",
			"public-resources template %s looks like a configuration-scan template", tmpl.ID)
	}
}

func TestPublicResourcesTemplateLoader_UniqueIDs(t *testing.T) {
	loader, err := publicresources.NewLoader()
	require.NoError(t, err)

	seen := make(map[string]int)
	for _, tmpl := range loader.GetTemplates() {
		seen[tmpl.ID]++
	}
	for id, count := range seen {
		assert.Equal(t, 1, count, "duplicate template ID: %s appears %d times", id, count)
	}
}

func TestResultToRisk(t *testing.T) {
	result := templates.ARGQueryResult{
		TemplateID: "storage_accounts_public_access",
		TemplateDetails: &templates.ARGQueryTemplate{
			ID:       "storage_accounts_public_access",
			Name:     "Publicly Accessible Storage Accounts",
			Severity: output.RiskSeverityHigh,
		},
		ResourceID:     "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mystorage",
		ResourceName:   "mystorage",
		ResourceType:   "Microsoft.Storage/storageAccounts",
		SubscriptionID: "xxx",
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		err := resultToRisk(result, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	risk, ok := items[0].(output.AurelianRisk)
	require.True(t, ok)

	assert.Equal(t, "public-azure-resource-storage-storageaccounts", risk.Name)
	assert.Equal(t, "Microsoft.Storage/storageAccounts", risk.DeduplicationID)
	assert.Equal(t, output.RiskSeverityHigh, risk.Severity)
	assert.Equal(t, "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mystorage", risk.ImpactedResourceID)
	assert.NotEmpty(t, risk.Context)

	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &ctx))
	assert.Equal(t, "storage_accounts_public_access", ctx["templateId"])
	assert.Equal(t, "mystorage", ctx["resourceName"])
	assert.Equal(t, "Microsoft.Storage/storageAccounts", ctx["resourceType"])
	assert.Equal(t, "xxx", ctx["subscriptionId"])
}

func TestResultToRisk_SeverityPreserved(t *testing.T) {
	severities := []string{"low", "medium", "high", "critical"}

	for _, sev := range severities {
		t.Run(sev, func(t *testing.T) {
			tmpl := &templates.ARGQueryTemplate{
				ID:       "test_" + sev,
				Name:     "Test " + sev,
				Severity: output.RiskSeverity(sev),
			}
			result := templates.ARGQueryResult{
				TemplateID:      tmpl.ID,
				TemplateDetails: tmpl,
				ResourceID:      "/subscriptions/s/resourceGroups/r/providers/T/n",
				ResourceType:    "Microsoft.Test/resources",
			}

			out := pipeline.New[model.AurelianModel]()
			go func() {
				defer out.Close()
				resultToRisk(result, out)
			}()

			items, err := out.Collect()
			require.NoError(t, err)
			require.Len(t, items, 1)

			risk := items[0].(output.AurelianRisk)
			assert.Equal(t, output.RiskSeverity(sev), risk.Severity)
			assert.Equal(t, "public-azure-resource-test-resources", risk.Name)
		})
	}
}

func TestResultToRisk_ContextContainsAllFields(t *testing.T) {
	result := templates.ARGQueryResult{
		TemplateID: "key_vault_public_access",
		TemplateDetails: &templates.ARGQueryTemplate{
			ID:       "key_vault_public_access",
			Name:     "Publicly Accessible Key Vaults",
			Severity: output.RiskSeverityHigh,
		},
		ResourceID:     "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/myvault",
		ResourceName:   "myvault",
		ResourceType:   "Microsoft.KeyVault/vaults",
		SubscriptionID: "sub-1",
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		resultToRisk(result, out)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	risk := items[0].(output.AurelianRisk)
	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &ctx))

	// All expected context fields must be present.
	assert.Equal(t, "key_vault_public_access", ctx["templateId"])
	assert.Equal(t, "myvault", ctx["resourceName"])
	assert.Equal(t, "Microsoft.KeyVault/vaults", ctx["resourceType"])
	assert.Equal(t, "sub-1", ctx["subscriptionId"])
	assert.Equal(t, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/myvault", ctx["resourceId"])
}
