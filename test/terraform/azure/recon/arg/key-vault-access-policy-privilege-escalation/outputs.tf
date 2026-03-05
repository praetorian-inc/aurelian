output "resource_group_name" {
  description = "Name of the resource group containing all test resources"
  value       = azurerm_resource_group.main.name
}

output "test_summary" {
  description = "Summary of deployed resources and expected detection results"
  value = {
    resource_group = azurerm_resource_group.main.name
    location       = azurerm_resource_group.main.location

    public_resources = {
      kv_access_policy = var.enable_tp ? azurerm_key_vault.access_policy[0].name : "disabled"
    }

    private_resources = var.enable_tn ? {
      kv_rbac = azurerm_key_vault.rbac[0].name
    } : {}

    expected_detections     = var.enable_tp ? 1 : 0
    expected_non_detections = var.enable_tn ? 1 : 0
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA KEY VAULT ACCESS POLICY PRIV ESC TESTING
    ============================================

    Template: key_vault_access_policy_privilege_escalation
    Resource Group: ${azurerm_resource_group.main.name}

    TP: Key Vault "${var.enable_tp ? azurerm_key_vault.access_policy[0].name : "disabled"}" (access policies, no RBAC)
    TN: Key Vault "${var.enable_tn ? azurerm_key_vault.rbac[0].name : "disabled"}" (RBAC authorization enabled)

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t key_vault_access_policy_privilege_escalation \
        -o /tmp/nebula-kv-privesc-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
