package misconfigcheck

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseResource_Standard(t *testing.T) {
	result := templates.ARGQueryResult{
		ResourceID:     "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm",
		SubscriptionID: "sub-123",
		ResourceName:   "my-vm",
	}
	sub, rg, name, err := ParseResource(result)
	require.NoError(t, err)
	assert.Equal(t, "sub-123", sub)
	assert.Equal(t, "my-rg", rg)
	assert.Equal(t, "my-vm", name)
}

func TestParseResource_CaseInsensitiveResourceGroups(t *testing.T) {
	result := templates.ARGQueryResult{
		ResourceID:     "/subscriptions/sub-1/RESOURCEGROUPS/My-RG/providers/Microsoft.Web/sites/app",
		SubscriptionID: "sub-1",
		ResourceName:   "app",
	}
	_, rg, _, err := ParseResource(result)
	require.NoError(t, err)
	assert.Equal(t, "My-RG", rg)
}

func TestParseResource_MissingSubscriptionID(t *testing.T) {
	result := templates.ARGQueryResult{
		ResourceID:     "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
		SubscriptionID: "",
		ResourceName:   "vm",
	}
	_, _, _, err := ParseResource(result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sub=\"\"")
}

func TestParseResource_MissingResourceGroup(t *testing.T) {
	result := templates.ARGQueryResult{
		ResourceID:     "/subscriptions/sub-1/providers/Microsoft.Compute/virtualMachines/vm",
		SubscriptionID: "sub-1",
		ResourceName:   "vm",
	}
	_, _, _, err := ParseResource(result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rg=\"\"")
}

func TestParseResource_MissingName(t *testing.T) {
	result := templates.ARGQueryResult{
		ResourceID:     "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
		SubscriptionID: "sub-1",
		ResourceName:   "",
	}
	_, _, _, err := ParseResource(result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name=\"\"")
}

func TestTemplatesNeedingEnrichment_ExactSet(t *testing.T) {
	expected := []string{
		"app_service_auth_disabled",
		"app_service_remote_debugging_enabled",
		"databases_allow_azure_services",
		"function_app_http_anonymous_access",
		"vm_privileged_managed_identity",
	}

	assert.Len(t, TemplatesNeedingEnrichment, len(expected))
	for _, id := range expected {
		assert.True(t, TemplatesNeedingEnrichment[id], "missing: %s", id)
	}
}

func TestTemplatesNeedingEnrichment_ARGFilteredNotIncluded(t *testing.T) {
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

	for _, id := range argFilteredTemplates {
		assert.False(t, TemplatesNeedingEnrichment[id],
			"%s should NOT need enrichment (has ARG-level filtering)", id)
	}
}

func TestIsAllowAzureServicesRule(t *testing.T) {
	assert.True(t, isAllowAzureServicesRule("0.0.0.0", "0.0.0.0"))
	assert.False(t, isAllowAzureServicesRule("10.0.0.1", "10.0.0.1"))
	assert.False(t, isAllowAzureServicesRule("0.0.0.0", "255.255.255.255"))
	assert.False(t, isAllowAzureServicesRule("", ""))
}

func TestUUIDPattern(t *testing.T) {
	assert.True(t, uuidPattern.MatchString("8e3af657-a8ff-443c-a75c-2fe8c4bcb635"))
	assert.True(t, uuidPattern.MatchString("B24988AC-6180-42A0-AB88-20F7382DD24C"))
	assert.False(t, uuidPattern.MatchString("not-a-uuid"))
	assert.False(t, uuidPattern.MatchString(""))
	assert.False(t, uuidPattern.MatchString("' OR 1=1 --"))
}

func TestPrivilegedRoleIDs_ExactSet(t *testing.T) {
	assert.Len(t, privilegedRoleIDs, 3)
	assert.True(t, privilegedRoleIDs["8e3af657-a8ff-443c-a75c-2fe8c4bcb635"], "Owner missing")
	assert.True(t, privilegedRoleIDs["b24988ac-6180-42a0-ab88-20f7382dd24c"], "Contributor missing")
	assert.True(t, privilegedRoleIDs["18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"], "User Access Admin missing")
}

func TestDerefStr(t *testing.T) {
	s := "hello"
	assert.Equal(t, "hello", derefStr(&s))
	assert.Equal(t, "", derefStr(nil))
}
