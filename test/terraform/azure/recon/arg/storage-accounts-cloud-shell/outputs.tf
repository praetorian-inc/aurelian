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
      cs_name_pattern = var.enable_tp_name ? azurerm_storage_account.cs_name_pattern[0].name : "disabled"
      cs_tagged       = var.enable_tp_tag ? azurerm_storage_account.cs_tagged[0].name : "disabled"
    }

    private_resources = var.enable_tn ? {
      regular_storage = azurerm_storage_account.regular[0].name
    } : {}

    expected_detections     = (var.enable_tp_name ? 1 : 0) + (var.enable_tp_tag ? 1 : 0)
    expected_non_detections = var.enable_tn ? 1 : 0
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA CLOUD SHELL STORAGE DETECTION TESTING
    ============================================

    Template: cloud_shell_storage_detection
    Resource Group: ${azurerm_resource_group.main.name}

    TP1: Storage "${var.enable_tp_name ? azurerm_storage_account.cs_name_pattern[0].name : "disabled"}" (cs + 18 hex chars naming pattern)
    TP2: Storage "${var.enable_tp_tag ? azurerm_storage_account.cs_tagged[0].name : "disabled"}" (ms-resource-usage=azure-cloud-shell tag)
    TN:  Storage "${var.enable_tn ? azurerm_storage_account.regular[0].name : "disabled"}" (regular storage, no CS indicators)

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t cloud_shell_storage_detection \
        -o /tmp/nebula-cs-storage-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
