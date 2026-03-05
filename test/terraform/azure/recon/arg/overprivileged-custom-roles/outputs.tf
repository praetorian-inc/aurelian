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
      overprivileged_role = var.enable_tp ? azurerm_role_definition.overprivileged[0].name : "disabled"
    }

    private_resources = var.enable_tn ? {
      safe_role = azurerm_role_definition.safe[0].name
    } : {}

    expected_detections     = var.enable_tp ? 1 : 0
    expected_non_detections = var.enable_tn ? 1 : 0
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA OVERPRIVILEGED CUSTOM ROLES TESTING
    ============================================

    Template: overprivileged_custom_roles
    Resource Group: ${azurerm_resource_group.main.name}

    TP: Custom role "${var.enable_tp ? azurerm_role_definition.overprivileged[0].name : "disabled"}" (has roleAssignments/write)
    TN: Custom role "${var.enable_tn ? azurerm_role_definition.safe[0].name : "disabled"}" (read-only)

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t overprivileged_custom_roles \
        -o /tmp/nebula-custom-roles-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
