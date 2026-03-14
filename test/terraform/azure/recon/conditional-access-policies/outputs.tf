output "tenant_id" {
  value = data.azuread_client_config.current.tenant_id
}

output "random_suffix" {
  value = random_string.suffix.result
}

# ---------- Policy 1: MFA admins ----------

output "mfa_admins_policy_id" {
  value = azuread_conditional_access_policy.mfa_admins.id
}

output "mfa_admins_policy_display_name" {
  value = azuread_conditional_access_policy.mfa_admins.display_name
}

# ---------- Policy 2: Device compliance ----------

output "device_compliance_policy_id" {
  value = azuread_conditional_access_policy.device_compliance.id
}

output "device_compliance_policy_display_name" {
  value = azuread_conditional_access_policy.device_compliance.display_name
}

# ---------- Policy 3: Risk-based ----------

output "risk_based_policy_id" {
  value = azuread_conditional_access_policy.risk_based.id
}

output "risk_based_policy_display_name" {
  value = azuread_conditional_access_policy.risk_based.display_name
}

# ---------- Policy 4: App-targeted ----------

output "app_targeted_policy_id" {
  value = azuread_conditional_access_policy.app_targeted.id
}

output "app_targeted_policy_display_name" {
  value = azuread_conditional_access_policy.app_targeted.display_name
}

# ---------- Policy 5: Location-based ----------

output "location_based_policy_id" {
  value = azuread_conditional_access_policy.location_based.id
}

output "location_based_policy_display_name" {
  value = azuread_conditional_access_policy.location_based.display_name
}

# ---------- Policy 6: Block legacy auth ----------

output "block_legacy_auth_policy_id" {
  value = azuread_conditional_access_policy.block_legacy_auth.id
}

output "block_legacy_auth_policy_display_name" {
  value = azuread_conditional_access_policy.block_legacy_auth.display_name
}

# ---------- Policy 7: Require password change ----------

output "require_password_change_policy_id" {
  value = azuread_conditional_access_policy.require_password_change.id
}

output "require_password_change_policy_display_name" {
  value = azuread_conditional_access_policy.require_password_change.display_name
}

# ---------- Policy 8: Azure management MFA ----------

output "azure_mgmt_mfa_policy_id" {
  value = azuread_conditional_access_policy.azure_mgmt_mfa.id
}

output "azure_mgmt_mfa_policy_display_name" {
  value = azuread_conditional_access_policy.azure_mgmt_mfa.display_name
}

# ---------- Policy 9: Mobile approved apps ----------

output "mobile_approved_apps_policy_id" {
  value = azuread_conditional_access_policy.mobile_approved_apps.id
}

output "mobile_approved_apps_policy_display_name" {
  value = azuread_conditional_access_policy.mobile_approved_apps.display_name
}

# ---------- Policy 10: Guest access ----------

output "guest_access_policy_id" {
  value = azuread_conditional_access_policy.guest_access.id
}

output "guest_access_policy_display_name" {
  value = azuread_conditional_access_policy.guest_access.display_name
}

# ---------- User outputs ----------

output "test_user_object_id" {
  value = azuread_user.test.object_id
}

output "test_user_display_name" {
  value = azuread_user.test.display_name
}

output "test_user_upn" {
  value = azuread_user.test.user_principal_name
}

output "exclude_user_object_id" {
  value = azuread_user.exclude.object_id
}

output "exclude_user_display_name" {
  value = azuread_user.exclude.display_name
}

output "admin_user_object_id" {
  value = azuread_user.admin.object_id
}

output "admin_user_display_name" {
  value = azuread_user.admin.display_name
}

# ---------- Group outputs ----------

output "test_group_object_id" {
  value = azuread_group.test.object_id
}

output "test_group_display_name" {
  value = azuread_group.test.display_name
}

output "admin_group_object_id" {
  value = azuread_group.admin.object_id
}

output "admin_group_display_name" {
  value = azuread_group.admin.display_name
}

# ---------- Application outputs ----------

output "test_app_client_id" {
  value = azuread_application.test.client_id
}

output "test_app_display_name" {
  value = azuread_application.test.display_name
}

output "test_service_principal_id" {
  value = azuread_service_principal.test.object_id
}

# ---------- Named location outputs ----------

output "named_location_id" {
  value = azuread_named_location.test.id
}

output "named_location_display_name" {
  value = azuread_named_location.test.display_name
}

# ---------- Role template outputs ----------

output "global_admin_role_template_id" {
  value = local.global_admin_role_template_id
}

output "security_reader_role_template_id" {
  value = local.security_reader_role_template_id
}

output "exchange_admin_role_template_id" {
  value = local.exchange_admin_role_template_id
}

output "user_admin_role_template_id" {
  value = local.user_admin_role_template_id
}

output "helpdesk_admin_role_template_id" {
  value = local.helpdesk_admin_role_template_id
}

output "security_admin_role_template_id" {
  value = local.security_admin_role_template_id
}

output "azure_management_app_id" {
  value = local.azure_management_app_id
}

# ---------- All policy IDs for bulk assertion ----------

output "all_policy_ids" {
  value = [
    azuread_conditional_access_policy.mfa_admins.id,
    azuread_conditional_access_policy.device_compliance.id,
    azuread_conditional_access_policy.risk_based.id,
    azuread_conditional_access_policy.app_targeted.id,
    azuread_conditional_access_policy.location_based.id,
    azuread_conditional_access_policy.block_legacy_auth.id,
    azuread_conditional_access_policy.require_password_change.id,
    azuread_conditional_access_policy.azure_mgmt_mfa.id,
    azuread_conditional_access_policy.mobile_approved_apps.id,
    azuread_conditional_access_policy.guest_access.id,
  ]
}
