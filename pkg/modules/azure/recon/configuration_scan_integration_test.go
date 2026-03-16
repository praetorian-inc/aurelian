//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/enrichers"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/evaluators"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureConfigurationScan(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/configuration-scan")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "configuration-scan")
	if !ok {
		t.Fatal("configuration-scan module not registered")
	}

	subscriptionID := fixture.Output("subscription_id")
	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"subscription-ids": []string{subscriptionID},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 8)

	// Collect risks and index by template ID → list of risks.
	type riskWithContext struct {
		Risk      output.AurelianRisk
		CtxMap    map[string]any
		Template  string
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
			Risk:      risk,
			CtxMap:    ctx,
			Template:  tid,
			ResourceID: risk.ImpactedResourceID,
		}
		all = append(all, rc)
		byTemplate[tid] = append(byTemplate[tid], rc)
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

	// =====================================================================
	// 1. AKS local accounts enabled
	// =====================================================================
	t.Run("aks_local_accounts_enabled", func(t *testing.T) {
		rc := findRisk(t, "aks_local_accounts_enabled", "aks_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("low"), rc.Risk.Severity)
		assert.Equal(t, "aks_local_accounts_enabled", rc.Template)
		assert.NotEmpty(t, rc.Risk.Context)
	})

	// =====================================================================
	// 2. App Service auth disabled (enricher-confirmed)
	// =====================================================================
	t.Run("app_service_auth_disabled", func(t *testing.T) {
		rc := findRisk(t, "app_service_auth_disabled", "webapp_no_auth_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("medium"), rc.Risk.Severity)
		assert.Equal(t, "app_service_auth_disabled", rc.Template)

		// The debug web app (remote_debug) should NOT appear here if it has auth
		// enabled — enricher should have dropped it. We don't assert this because
		// it also has auth disabled in this fixture (no auth_settings_v2 block).
	})

	// =====================================================================
	// 3. App Service remote debugging enabled (enricher-confirmed)
	// =====================================================================
	t.Run("app_service_remote_debugging_enabled", func(t *testing.T) {
		rc := findRisk(t, "app_service_remote_debugging_enabled", "webapp_debug_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("high"), rc.Risk.Severity)
		assert.Equal(t, "app_service_remote_debugging_enabled", rc.Template)

		// The no-auth web app should NOT appear in remote debugging findings
		// because remote_debugging_enabled defaults to false.
		noAuthID := strings.ToLower(fixture.Output("webapp_no_auth_id"))
		for _, rc := range byTemplate["app_service_remote_debugging_enabled"] {
			assert.NotEqual(t, noAuthID, strings.ToLower(rc.ResourceID),
				"no-auth web app should not be flagged for remote debugging")
		}
	})

	// =====================================================================
	// 4. SQL Server with Azure services firewall (enricher-confirmed)
	// =====================================================================
	t.Run("databases_allow_azure_services", func(t *testing.T) {
		rc := findRisk(t, "databases_allow_azure_services", "sql_server_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("high"), rc.Risk.Severity)
		assert.Equal(t, "databases_allow_azure_services", rc.Template)
	})

	// =====================================================================
	// 5. Function App anonymous HTTP trigger (enricher-confirmed)
	// The fixture deploys a Node.js function with authLevel:anonymous
	// via zip_deploy_file.
	// =====================================================================
	t.Run("function_app_http_anonymous_access", func(t *testing.T) {
		rc := findRisk(t, "function_app_http_anonymous_access", "func_anon_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("high"), rc.Risk.Severity)
		assert.Equal(t, "function_app_http_anonymous_access", rc.Template)
	})

	// =====================================================================
	// 6. Function App with admin managed identity (ARG-level join)
	// =====================================================================
	t.Run("function_apps_admin_managed_identity", func(t *testing.T) {
		rc := findRisk(t, "function_apps_admin_managed_identity", "func_admin_mi_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("low"), rc.Risk.Severity)
		assert.Equal(t, "function_apps_admin_managed_identity", rc.Template)
	})

	// =====================================================================
	// 7. Key Vault without RBAC authorization
	// =====================================================================
	t.Run("key_vault_access_policy_privilege_escalation", func(t *testing.T) {
		rc := findRisk(t, "key_vault_access_policy_privilege_escalation", "key_vault_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("high"), rc.Risk.Severity)
		assert.Equal(t, "key_vault_access_policy_privilege_escalation", rc.Template)
	})

	// =====================================================================
	// 8. Kusto cluster with wildcard trusted tenants
	// =====================================================================
	t.Run("kusto_wildcard_trusted_tenants", func(t *testing.T) {
		rc := findRisk(t, "kusto_wildcard_trusted_tenants", "kusto_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("high"), rc.Risk.Severity)
		assert.Equal(t, "kusto_wildcard_trusted_tenants", rc.Template)
	})

	// =====================================================================
	// 9. NSG with unrestricted port ranges
	// =====================================================================
	t.Run("nsg_unrestricted_port_ranges", func(t *testing.T) {
		rc := findRisk(t, "nsg_unrestricted_port_ranges", "nsg_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("medium"), rc.Risk.Severity)
		assert.Equal(t, "nsg_unrestricted_port_ranges", rc.Template)
	})

	// =====================================================================
	// 10. Overprivileged custom role
	// =====================================================================
	t.Run("overprivileged_custom_roles", func(t *testing.T) {
		rc := findRisk(t, "overprivileged_custom_roles", "custom_role_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("high"), rc.Risk.Severity)
		assert.Equal(t, "overprivileged_custom_roles", rc.Template)
	})

	// =====================================================================
	// 11. VM with privileged managed identity (enricher-confirmed)
	// =====================================================================
	t.Run("vm_privileged_managed_identity", func(t *testing.T) {
		rc := findRisk(t, "vm_privileged_managed_identity", "vm_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("low"), rc.Risk.Severity)
		assert.Equal(t, "vm_privileged_managed_identity", rc.Template)
	})

	// =====================================================================
	// 12. VM SSH password authentication
	// =====================================================================
	t.Run("vm_ssh_password_authentication", func(t *testing.T) {
		rc := findRisk(t, "vm_ssh_password_authentication", "vm_id")
		assert.Equal(t, "azure-configuration-scan", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverity("high"), rc.Risk.Severity)
		assert.Equal(t, "vm_ssh_password_authentication", rc.Template)
	})

	// =====================================================================
	// Cross-finding invariants
	// =====================================================================

	t.Run("all risks have name azure-configuration-scan", func(t *testing.T) {
		for _, rc := range all {
			assert.Equal(t, "azure-configuration-scan", rc.Risk.Name,
				"template %q: risk name should be azure-configuration-scan", rc.Template)
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

	t.Run("all fixture resources detected", func(t *testing.T) {
		for _, id := range fixture.OutputList("all_resource_ids") {
			testutil.AssertResultContainsString(t, results, id)
		}
	})

	// =====================================================================
	// Negative assertions — correctly configured resources NOT detected
	// =====================================================================

	t.Run("web app with auth enabled NOT flagged for auth_disabled", func(t *testing.T) {
		authOKID := strings.ToLower(fixture.Output("webapp_with_auth_id"))
		require.NotEmpty(t, authOKID)
		for _, rc := range byTemplate["app_service_auth_disabled"] {
			assert.NotEqual(t, authOKID, strings.ToLower(rc.ResourceID),
				"web app with auth enabled should be dropped by enricher")
		}
	})

	t.Run("web app with auth enabled NOT flagged for remote_debugging", func(t *testing.T) {
		authOKID := strings.ToLower(fixture.Output("webapp_with_auth_id"))
		for _, rc := range byTemplate["app_service_remote_debugging_enabled"] {
			assert.NotEqual(t, authOKID, strings.ToLower(rc.ResourceID),
				"web app with auth (no remote debug) should be dropped by enricher")
		}
	})

	t.Run("key vault with RBAC NOT flagged for access_policy_privilege_escalation", func(t *testing.T) {
		kvRBACID := strings.ToLower(fixture.Output("key_vault_with_rbac_id"))
		require.NotEmpty(t, kvRBACID)
		for _, rc := range byTemplate["key_vault_access_policy_privilege_escalation"] {
			assert.NotEqual(t, kvRBACID, strings.ToLower(rc.ResourceID),
				"key vault with RBAC should NOT be flagged")
		}
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
}
