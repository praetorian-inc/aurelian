package evaluators

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisteredEvaluators_ExactSet(t *testing.T) {
	evaluatorTemplates := []string{
		"app_service_auth_disabled",
		"app_service_remote_debugging_enabled",
		"databases_allow_azure_services",
		"function_app_http_anonymous_access",
		"vm_privileged_managed_identity",
	}

	for _, tmplID := range evaluatorTemplates {
		_, ok := plugin.GetAzureEvaluator(tmplID)
		assert.True(t, ok, "template %q should have a registered evaluator", tmplID)
	}
}

func TestRegisteredEvaluators_ARGFilteredNotIncluded(t *testing.T) {
	argFilteredTemplates := []string{
		"aks_local_accounts_enabled",
		"aks_rbac_disabled",
		"key_vault_access_policy_privilege_escalation",
		"kusto_wildcard_trusted_tenants",
		"nsg_unrestricted_port_ranges",
		"overprivileged_custom_roles",
		"vm_ssh_password_authentication",
		"function_apps_admin_managed_identity",
	}

	for _, tmplID := range argFilteredTemplates {
		_, ok := plugin.GetAzureEvaluator(tmplID)
		assert.False(t, ok, "template %q should NOT have an evaluator (ARG-filtered)", tmplID)
	}
}

func TestEvaluator_AppServiceAuthDisabled(t *testing.T) {
	eval, ok := plugin.GetAzureEvaluator("app_service_auth_disabled")
	require.True(t, ok)

	assert.True(t, eval(templates.ARGQueryResult{Properties: map[string]any{"authEnabled": false}}))
	assert.False(t, eval(templates.ARGQueryResult{Properties: map[string]any{"authEnabled": true}}))
	assert.False(t, eval(templates.ARGQueryResult{Properties: map[string]any{}}))
}

func TestEvaluator_RemoteDebuggingEnabled(t *testing.T) {
	eval, ok := plugin.GetAzureEvaluator("app_service_remote_debugging_enabled")
	require.True(t, ok)

	assert.True(t, eval(templates.ARGQueryResult{Properties: map[string]any{"remoteDebuggingEnabled": true}}))
	assert.False(t, eval(templates.ARGQueryResult{Properties: map[string]any{"remoteDebuggingEnabled": false}}))
	assert.False(t, eval(templates.ARGQueryResult{Properties: map[string]any{}}))
}

func TestEvaluator_DatabasesAllowAzureServices(t *testing.T) {
	eval, ok := plugin.GetAzureEvaluator("databases_allow_azure_services")
	require.True(t, ok)

	assert.True(t, eval(templates.ARGQueryResult{Properties: map[string]any{"allowAzureServicesFirewall": true}}))
	assert.False(t, eval(templates.ARGQueryResult{Properties: map[string]any{"allowAzureServicesFirewall": false}}))
	assert.False(t, eval(templates.ARGQueryResult{Properties: map[string]any{}}))
}

func TestEvaluator_FunctionAppAnonymousAccess(t *testing.T) {
	eval, ok := plugin.GetAzureEvaluator("function_app_http_anonymous_access")
	require.True(t, ok)

	assert.True(t, eval(templates.ARGQueryResult{Properties: map[string]any{"hasAnonymousHttpTrigger": true}}))
	assert.False(t, eval(templates.ARGQueryResult{Properties: map[string]any{"hasAnonymousHttpTrigger": false}}))
}

func TestEvaluator_VMPrivilegedManagedIdentity(t *testing.T) {
	eval, ok := plugin.GetAzureEvaluator("vm_privileged_managed_identity")
	require.True(t, ok)

	assert.True(t, eval(templates.ARGQueryResult{Properties: map[string]any{"hasPrivilegedManagedIdentity": true}}))
	assert.False(t, eval(templates.ARGQueryResult{Properties: map[string]any{"hasPrivilegedManagedIdentity": false}}))
}
