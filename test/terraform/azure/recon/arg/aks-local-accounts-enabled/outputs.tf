output "resource_group_name" {
  description = "Name of the resource group containing all test resources"
  value       = azurerm_resource_group.main.name
}

output "test_summary" {
  description = "Summary of deployed resources and expected detection results"
  value = {
    resource_group = azurerm_resource_group.main.name
    location       = azurerm_resource_group.main.location

    public_resources = var.enable_aks ? {
      aks_local_enabled = azurerm_kubernetes_cluster.local_enabled[0].name
    } : {}

    private_resources = var.enable_aks ? {
      aks_local_disabled = azurerm_kubernetes_cluster.local_disabled[0].name
    } : {}

    expected_detections     = var.enable_aks ? 1 : 0
    expected_non_detections = var.enable_aks ? 1 : 0
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA AKS LOCAL ACCOUNTS TESTING
    ============================================

    Template: aks_local_accounts_enabled
    Resource Group: ${azurerm_resource_group.main.name}

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t aks_local_accounts_enabled \
        -o /tmp/nebula-aks-local-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
