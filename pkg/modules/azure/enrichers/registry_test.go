package enrichers

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestRegisteredEnrichers_ExactSet(t *testing.T) {
	enricherResourceTypes := []string{
		"microsoft.web/sites",
		"microsoft.sql/servers",
		"microsoft.synapse/workspaces",
		"microsoft.dbforpostgresql/flexibleservers",
		"microsoft.dbformysql/flexibleservers",
		"microsoft.compute/virtualmachines",
	}

	for _, rt := range enricherResourceTypes {
		assert.NotEmpty(t, plugin.GetAzureEnrichers(rt),
			"resource type %q should have a registered enricher", rt)
	}
}

func TestRegisteredEnrichers_WebSitesHasMultiple(t *testing.T) {
	enrichers := plugin.GetAzureEnrichers("microsoft.web/sites")
	assert.Len(t, enrichers, 3,
		"microsoft.web/sites should have 3 enrichers (auth, remote debugging, function anonymous)")
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
