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
      app_debug_enabled = azurerm_linux_web_app.debug_enabled.name
    }

    private_resources = {
      app_debug_disabled = azurerm_linux_web_app.debug_disabled.name
    }

    expected_detections     = 1
    expected_non_detections = 1
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA APP SERVICE REMOTE DEBUGGING TESTING
    ============================================

    Template: app_service_remote_debugging_enabled
    Resource Group: ${azurerm_resource_group.main.name}

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t app_service_remote_debugging_enabled \
        -o /tmp/nebula-debug-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
