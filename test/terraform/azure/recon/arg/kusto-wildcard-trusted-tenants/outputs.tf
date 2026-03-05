output "resource_group_name" {
  description = "Name of the resource group containing all test resources"
  value       = azurerm_resource_group.main.name
}

output "test_summary" {
  description = "Summary of deployed resources and expected detection results"
  value = {
    resource_group = azurerm_resource_group.main.name
    location       = azurerm_resource_group.main.location

    public_resources = var.enable_kusto ? {
      kusto_wildcard = azurerm_kusto_cluster.wildcard[0].name
    } : {}

    private_resources = var.enable_kusto_tn ? {
      kusto_restricted = azurerm_kusto_cluster.restricted[0].name
    } : {}

    expected_detections     = var.enable_kusto ? 1 : 0
    expected_non_detections = var.enable_kusto_tn ? 1 : 0

    notes = "Kusto clusters take ~15 min to provision. TN requires post-deploy az CLI step to restrict tenants."
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA KUSTO WILDCARD TRUSTED TENANTS TESTING
    ============================================

    Template: kusto_wildcard_trusted_tenants
    Resource Group: ${azurerm_resource_group.main.name}

    NOTE: Kusto clusters take ~15 min to provision!

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t kusto_wildcard_trusted_tenants \
        -o /tmp/nebula-kusto-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
