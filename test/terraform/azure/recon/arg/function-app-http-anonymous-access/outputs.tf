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
      func_anonymous = azurerm_windows_function_app.anonymous_triggers.name
    }

    private_resources = {
      func_keyed      = azurerm_windows_function_app.keyed_triggers.name
      webapp_not_func = azurerm_linux_web_app.not_func.name
    }

    expected_detections     = 1
    expected_non_detections = 2

    notes = "You MUST deploy actual function code with authLevel=anonymous/function to the respective Function Apps for the enricher to detect them."
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA FUNCTION APP ANONYMOUS ACCESS TESTING
    ============================================

    Template: function_app_http_anonymous_access
    Resource Group: ${azurerm_resource_group.main.name}

    IMPORTANT: Deploy function code after terraform apply:
      # For TP (anonymous):
      cd /tmp/func-anon && func init --python
      func new --template "HTTP trigger" --name HttpAnon
      # Edit function.json: set "authLevel": "anonymous"
      func azure functionapp publish ${azurerm_windows_function_app.anonymous_triggers.name}

      # For TN (keyed):
      cd /tmp/func-keyed && func init --python
      func new --template "HTTP trigger" --name HttpKeyed
      # Keep default "authLevel": "function"
      func azure functionapp publish ${azurerm_windows_function_app.keyed_triggers.name}

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t function_app_http_anonymous_access \
        -o /tmp/nebula-func-anon-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
