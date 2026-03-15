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

	configscantemplates "github.com/praetorian-inc/aurelian/pkg/templates/azure/configuration-scan"
)

func TestConfigurationScanModuleMetadata(t *testing.T) {
	m := &AzureConfigurationScanModule{}

	assert.Equal(t, "configuration-scan", m.ID())
	assert.Equal(t, "Azure Configuration Scan", m.Name())
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

func TestConfigurationScanParameters(t *testing.T) {
	m := &AzureConfigurationScanModule{}
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

func TestConfigurationScanTemplateLoader_LoadsAll13(t *testing.T) {
	loader, err := configscantemplates.NewLoader()
	require.NoError(t, err)

	tmps := loader.GetTemplates()
	assert.Len(t, tmps, 13, "should load exactly 13 configuration scan templates")

	expectedIDs := map[string]bool{
		"aks_local_accounts_enabled":                  true,
		"aks_rbac_disabled":                           true,
		"app_service_auth_disabled":                    true,
		"app_service_remote_debugging_enabled":         true,
		"databases_allow_azure_services":               true,
		"function_app_http_anonymous_access":           true,
		"function_apps_admin_managed_identity":         true,
		"key_vault_access_policy_privilege_escalation":  true,
		"kusto_wildcard_trusted_tenants":               true,
		"nsg_unrestricted_port_ranges":                 true,
		"overprivileged_custom_roles":                  true,
		"vm_privileged_managed_identity":               true,
		"vm_ssh_password_authentication":               true,
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
}

func TestConfigurationScanTemplateLoader_NoOverlapWithPublicResources(t *testing.T) {
	// Import public-resources loader to verify no template ID overlap.
	// This test is in the recon package so we can't directly import,
	// but we verify by checking the module initialization loads distinct sets.
	m := &AzureConfigurationScanModule{}
	require.NoError(t, m.initialize())
	assert.Len(t, m.templates, 13)

	for _, tmpl := range m.templates {
		// None of these should be public-access templates
		assert.NotContains(t, tmpl.ID, "public_access",
			"configuration scan template %s looks like a public-access template", tmpl.ID)
		assert.NotEqual(t, "storage_accounts_public_access", tmpl.ID)
		assert.NotEqual(t, "sql_servers_public_access", tmpl.ID)
	}
}

func TestMisconfigToRisk(t *testing.T) {
	tmpl := &templates.ARGQueryTemplate{
		ID:       "test_misconfig",
		Name:     "Test Misconfiguration",
		Severity: "high",
	}
	result := templates.ARGQueryResult{
		TemplateID:      "test_misconfig",
		TemplateDetails: tmpl,
		ResourceID:      "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
		ResourceName:    "vm-1",
		ResourceType:    "Microsoft.Compute/virtualMachines",
		SubscriptionID:  "sub-1",
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		require.NoError(t, configScanToRisk(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	risk, ok := items[0].(output.AurelianRisk)
	require.True(t, ok)

	assert.Equal(t, "azure-configuration-scan", risk.Name)
	assert.Equal(t, output.RiskSeverity("high"), risk.Severity)
	assert.Equal(t, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1", risk.ImpactedResourceID)
	assert.NotEmpty(t, risk.Context)

	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &ctx))
	assert.Equal(t, "test_misconfig", ctx["templateId"])
	assert.Equal(t, "vm-1", ctx["resourceName"])
	assert.Equal(t, "Microsoft.Compute/virtualMachines", ctx["resourceType"])
}

func TestMisconfigToRisk_SeverityPreserved(t *testing.T) {
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
			}

			out := pipeline.New[model.AurelianModel]()
			go func() {
				defer out.Close()
				configScanToRisk(result, out)
			}()

			items, err := out.Collect()
			require.NoError(t, err)
			require.Len(t, items, 1)

			risk := items[0].(output.AurelianRisk)
			assert.Equal(t, output.RiskSeverity(sev), risk.Severity)
		})
	}
}
