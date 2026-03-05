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
      app_no_auth = azurerm_linux_web_app.no_auth.name
    }

    private_resources = {
      app_with_auth   = azurerm_linux_web_app.with_auth.name
      func_no_auth_fp = azurerm_windows_function_app.no_auth.name
    }

    expected_detections     = 1
    expected_non_detections = 2
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA APP SERVICE AUTH DISABLED TESTING
    ============================================

    Template: app_service_auth_disabled
    Resource Group: ${azurerm_resource_group.main.name}

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t app_service_auth_disabled \
        -o /tmp/nebula-auth-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
