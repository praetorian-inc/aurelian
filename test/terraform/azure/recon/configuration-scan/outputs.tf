output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "random_suffix" {
  value = random_string.suffix.result
}

# ---------- 1. AKS local accounts ----------

output "aks_id" {
  value = azurerm_kubernetes_cluster.local_accounts.id
}

output "aks_name" {
  value = azurerm_kubernetes_cluster.local_accounts.name
}

# ---------- 2. Web App no auth ----------

output "webapp_no_auth_id" {
  value = azurerm_linux_web_app.no_auth.id
}

output "webapp_no_auth_name" {
  value = azurerm_linux_web_app.no_auth.name
}

# ---------- 3. Web App remote debugging ----------

output "webapp_debug_id" {
  value = azurerm_linux_web_app.remote_debug.id
}

output "webapp_debug_name" {
  value = azurerm_linux_web_app.remote_debug.name
}

# ---------- 4. SQL Server with Azure services firewall ----------

output "sql_server_id" {
  value = azurerm_mssql_server.allow_azure.id
}

output "sql_server_name" {
  value = azurerm_mssql_server.allow_azure.name
}

# ---------- 5. Function App anonymous trigger ----------

output "func_anon_id" {
  value = azurerm_linux_function_app.anon_trigger.id
}

output "func_anon_name" {
  value = azurerm_linux_function_app.anon_trigger.name
}

# ---------- 6. Function App admin managed identity ----------

output "func_admin_mi_id" {
  value = azurerm_linux_function_app.admin_mi.id
}

output "func_admin_mi_name" {
  value = azurerm_linux_function_app.admin_mi.name
}

output "func_admin_mi_principal_id" {
  value = azurerm_linux_function_app.admin_mi.identity[0].principal_id
}

# ---------- 7. Key Vault no RBAC ----------

output "key_vault_id" {
  value = azurerm_key_vault.no_rbac.id
}

output "key_vault_name" {
  value = azurerm_key_vault.no_rbac.name
}

# ---------- 8. Kusto wildcard tenants ----------

output "kusto_id" {
  value = azurerm_kusto_cluster.wildcard.id
}

output "kusto_name" {
  value = azurerm_kusto_cluster.wildcard.name
}

# ---------- 9. NSG unrestricted ports ----------

output "nsg_id" {
  value = azurerm_network_security_group.wide_open.id
}

output "nsg_name" {
  value = azurerm_network_security_group.wide_open.name
}

# ---------- 10. Overprivileged custom role ----------

# ARG AuthorizationResources returns tenant-scoped IDs for role definitions
# (without subscription prefix), so we construct the matching format here.
output "custom_role_id" {
  value = "/providers/Microsoft.Authorization/roleDefinitions/${azurerm_role_definition.overprivileged.role_definition_id}"
}

output "custom_role_name" {
  value = azurerm_role_definition.overprivileged.name
}

# ---------- 11 + 12. Linux VM (privileged MI + password auth) ----------

output "vm_id" {
  value = azurerm_linux_virtual_machine.priv_mi_password.id
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.priv_mi_password.name
}

output "vm_principal_id" {
  value = azurerm_linux_virtual_machine.priv_mi_password.identity[0].principal_id
}

# ---------- All resource IDs for bulk assertion ----------

output "all_resource_ids" {
  value = [
    azurerm_kubernetes_cluster.local_accounts.id,
    azurerm_linux_web_app.no_auth.id,
    azurerm_linux_web_app.remote_debug.id,
    azurerm_mssql_server.allow_azure.id,
    azurerm_linux_function_app.anon_trigger.id,
    azurerm_linux_function_app.admin_mi.id,
    azurerm_key_vault.no_rbac.id,
    azurerm_kusto_cluster.wildcard.id,
    azurerm_network_security_group.wide_open.id,
    azurerm_linux_virtual_machine.priv_mi_password.id,
  ]
}

# ---------- Negative fixtures (should NOT be detected) ----------

output "webapp_with_auth_id" {
  value = azurerm_linux_web_app.with_auth.id
}

output "key_vault_with_rbac_id" {
  value = azurerm_key_vault.with_rbac.id
}

# ---------- Template ID → resource ID mapping for per-template assertions ----------

output "template_resource_map" {
  value = {
    aks_local_accounts_enabled                  = azurerm_kubernetes_cluster.local_accounts.id
    app_service_auth_disabled                    = azurerm_linux_web_app.no_auth.id
    app_service_remote_debugging_enabled         = azurerm_linux_web_app.remote_debug.id
    databases_allow_azure_services               = azurerm_mssql_server.allow_azure.id
    function_app_http_anonymous_access           = azurerm_linux_function_app.anon_trigger.id
    function_apps_admin_managed_identity         = azurerm_linux_function_app.admin_mi.id
    key_vault_access_policy_privilege_escalation  = azurerm_key_vault.no_rbac.id
    kusto_wildcard_trusted_tenants               = azurerm_kusto_cluster.wildcard.id
    nsg_unrestricted_port_ranges                 = azurerm_network_security_group.wide_open.id
    overprivileged_custom_roles                  = "/providers/Microsoft.Authorization/roleDefinitions/${azurerm_role_definition.overprivileged.role_definition_id}"
    vm_privileged_managed_identity               = azurerm_linux_virtual_machine.priv_mi_password.id
    vm_ssh_password_authentication               = azurerm_linux_virtual_machine.priv_mi_password.id
  }
}

# ---------- Expected template severities ----------

output "template_severity_map" {
  value = {
    aks_local_accounts_enabled                  = "low"
    app_service_auth_disabled                    = "medium"
    app_service_remote_debugging_enabled         = "high"
    databases_allow_azure_services               = "high"
    function_app_http_anonymous_access           = "high"
    function_apps_admin_managed_identity         = "low"
    key_vault_access_policy_privilege_escalation  = "high"
    kusto_wildcard_trusted_tenants               = "high"
    nsg_unrestricted_port_ranges                 = "medium"
    overprivileged_custom_roles                  = "high"
    vm_privileged_managed_identity               = "low"
    vm_ssh_password_authentication               = "high"
  }
}
