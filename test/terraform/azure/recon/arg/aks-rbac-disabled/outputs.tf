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
      aks_no_rbac = var.enable_aks_no_rbac ? "${local.pfx}-aks-norbac-${local.sfx}" : "disabled"
    }

    private_resources = var.enable_aks_rbac ? {
      aks_rbac_enabled = azurerm_kubernetes_cluster.rbac_enabled[0].name
    } : {}

    expected_detections     = var.enable_aks_no_rbac ? 1 : 0
    expected_non_detections = var.enable_aks_rbac ? 1 : 0
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA AKS RBAC DISABLED TESTING
    ============================================

    Template: aks_rbac_disabled
    Resource Group: ${azurerm_resource_group.main.name}

    NOTE: The TP cluster (RBAC disabled) is created via az CLI because
    the Terraform azurerm provider does not support disabling RBAC.

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t aks_rbac_disabled \
        -o /tmp/nebula-aks-rbac-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
