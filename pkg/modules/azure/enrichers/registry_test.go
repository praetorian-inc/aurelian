package enrichers

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestRegisteredEnrichers_ExactSet(t *testing.T) {
	enricherTemplates := []string{
		"app_service_auth_disabled",
		"app_service_remote_debugging_enabled",
		"databases_allow_azure_services",
		"function_app_http_anonymous_access",
		"vm_privileged_managed_identity",
	}

	for _, tmplID := range enricherTemplates {
		assert.NotEmpty(t, plugin.GetAzureEnrichers(tmplID),
			"template %q should have a registered enricher", tmplID)
	}
}

func TestRegisteredEnrichers_ARGFilteredNotIncluded(t *testing.T) {
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
		assert.Empty(t, plugin.GetAzureEnrichers(tmplID),
			"template %q should NOT have a registered enricher (ARG-level filtering)", tmplID)
	}
}
