output "resource_group_name" {
  description = "Name of the resource group containing all test resources"
  value       = azurerm_resource_group.main.name
}

output "test_summary" {
  description = "Summary of deployed resources and expected detection results"
  value = {
    resource_group = azurerm_resource_group.main.name
    location       = azurerm_resource_group.main.location

    public_resources = merge(
      {
        sql_allow_azure = azurerm_mssql_server.allow_azure.name
      },
      var.enable_postgresql ? {
        pg_allow_azure = azurerm_postgresql_flexible_server.allow_azure[0].name
      } : {},
      var.enable_mysql ? {
        mysql_allow_azure = azurerm_mysql_flexible_server.allow_azure[0].name
      } : {},
      var.enable_synapse ? {
        synapse_allow_azure = azurerm_synapse_workspace.allow_azure[0].name
      } : {}
    )

    private_resources = merge(
      {
        sql_no_azure = azurerm_mssql_server.no_azure.name
      },
      var.enable_postgresql ? {
        pg_no_azure = azurerm_postgresql_flexible_server.no_azure[0].name
      } : {},
      var.enable_mysql ? {
        mysql_no_azure = azurerm_mysql_flexible_server.no_azure[0].name
      } : {},
      var.enable_synapse ? {
        synapse_no_azure = azurerm_synapse_workspace.no_azure[0].name
      } : {}
    )

    expected_detections     = 1 + (var.enable_postgresql ? 1 : 0) + (var.enable_mysql ? 1 : 0) + (var.enable_synapse ? 1 : 0)
    expected_non_detections = 1 + (var.enable_postgresql ? 1 : 0) + (var.enable_mysql ? 1 : 0) + (var.enable_synapse ? 1 : 0)
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA DATABASES ALLOW AZURE SERVICES TESTING
    ============================================

    Template: databases_allow_azure_services
    Resource Group: ${azurerm_resource_group.main.name}

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t databases_allow_azure_services \
        -o /tmp/nebula-db-azure-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
