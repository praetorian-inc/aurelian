// Outputs consumed by the Go integration test for deterministic assertions.
// All outputs are flat strings to work with fixture.Output(key).

output "tenant_id" {
  value = data.azuread_client_config.current.tenant_id
}

output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "suffix" {
  value = random_string.suffix.result
}

output "domain" {
  value = var.domain
}

# ---- User Object IDs ----

output "user_global_admin_id" {
  value = azuread_user.global_admin.object_id
}

output "user_priv_role_admin_id" {
  value = azuread_user.priv_role_admin.object_id
}

output "user_app_admin_id" {
  value = azuread_user.app_admin.object_id
}

output "user_user_admin_id" {
  value = azuread_user.user_admin.object_id
}

output "user_auth_admin_id" {
  value = azuread_user.auth_admin.object_id
}

output "user_helpdesk_admin_id" {
  value = azuread_user.helpdesk_admin.object_id
}

output "user_password_admin_id" {
  value = azuread_user.password_admin.object_id
}

output "user_priv_auth_admin_id" {
  value = azuread_user.priv_auth_admin.object_id
}

output "user_groups_admin_id" {
  value = azuread_user.groups_admin.object_id
}

output "user_conditional_access_admin_id" {
  value = azuread_user.conditional_access_admin.object_id
}

output "user_exchange_admin_id" {
  value = azuread_user.exchange_admin.object_id
}

output "user_regular_id" {
  value = azuread_user.regular.object_id
}

# ---- Group Object IDs ----

output "group_privileged_id" {
  value = azuread_group.privileged.object_id
}

output "group_regular_id" {
  value = azuread_group.regular.object_id
}

# ---- Application / Service Principal IDs ----

output "privileged_app_object_id" {
  value = azuread_application.privileged.object_id
}

output "privileged_app_client_id" {
  value = azuread_application.privileged.client_id
}

output "privileged_sp_object_id" {
  value = azuread_service_principal.privileged.object_id
}

output "regular_app_object_id" {
  value = azuread_application.regular.object_id
}

output "regular_app_client_id" {
  value = azuread_application.regular.client_id
}

output "regular_sp_object_id" {
  value = azuread_service_principal.regular.object_id
}

# ---- Managed Identity IDs ----

output "mi_user_assigned_id" {
  value = azurerm_user_assigned_identity.test.id
}

output "mi_user_assigned_principal_id" {
  value = azurerm_user_assigned_identity.test.principal_id
}

output "mi_user_assigned_client_id" {
  value = azurerm_user_assigned_identity.test.client_id
}

output "vm_id" {
  value = azurerm_linux_virtual_machine.test.id
}

output "vm_principal_id" {
  value = azurerm_linux_virtual_machine.test.identity[0].principal_id
}

# ---- ARM Resource IDs ----

output "resource_group_id" {
  value = azurerm_resource_group.test.id
}

# ---- CLI User Object ID (for cross-subscription admin testing) ----

output "cli_user_object_id" {
  value = data.azuread_client_config.current.object_id
}

# ---- PIM Reader App (for PIM API access) ----

output "pim_app_client_id" {
  value = azuread_application.pim_reader.client_id
}

output "pim_app_client_secret" {
  value     = azuread_application_password.pim_reader.value
  sensitive = true
}

# ---- Microsoft Graph Service Principal ID (for app role targets) ----

output "msgraph_sp_object_id" {
  value = data.azuread_service_principal.msgraph.object_id
}
