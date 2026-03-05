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
      func_public_no_pe = azurerm_windows_function_app.public_no_pe.name
    }

    private_resources = merge(
      {
        func_access_disabled = azurerm_windows_function_app.private_disabled.name
        webapp_not_func      = azurerm_linux_web_app.public_webapp.name
      },
      var.enable_private_endpoint ? {
        func_public_with_pe = azurerm_windows_function_app.public_with_pe[0].name
      } : {}
    )

    expected_detections     = 1
    expected_non_detections = var.enable_private_endpoint ? 3 : 2
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA FUNCTION APPS PUBLIC EXPOSURE TESTING
    ============================================

    Template: function_apps_public_exposure
    Resource Group: ${azurerm_resource_group.main.name}

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t function_apps_public_exposure \
        -o /tmp/nebula-func-exposure-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
