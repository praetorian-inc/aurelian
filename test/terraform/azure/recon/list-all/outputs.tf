output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "resource_group_name" {
  value = azurerm_resource_group.test.name
}

output "resource_group_id" {
  value = azurerm_resource_group.test.id
}

output "func_resource_group_id" {
  value = azurerm_resource_group.func.id
}

output "vnet_id" {
  value = azurerm_virtual_network.test.id
}

output "nsg_id" {
  value = azurerm_network_security_group.test.id
}

output "storage_account_id" {
  value = azurerm_storage_account.test.id
}

output "key_vault_id" {
  value = azurerm_key_vault.test.id
}

output "log_analytics_id" {
  value = azurerm_log_analytics_workspace.test.id
}

output "acr_id" {
  value = azurerm_container_registry.test.id
}

output "data_factory_id" {
  value = azurerm_data_factory.test.id
}

output "event_grid_topic_id" {
  value = azurerm_eventgrid_topic.test.id
}

output "service_bus_id" {
  value = azurerm_servicebus_namespace.test.id
}

output "web_app_id" {
  value = azurerm_linux_web_app.test.id
}

output "function_app_id" {
  value = azurerm_linux_function_app.test.id
}

output "automation_account_id" {
  value = azurerm_automation_account.test.id
}

output "sql_server_id" {
  value = azurerm_mssql_server.test.id
}

output "vm_id" {
  value = azurerm_linux_virtual_machine.test.id
}

output "nic_id" {
  value = azurerm_network_interface.test.id
}

output "service_plan_id" {
  value = azurerm_service_plan.test.id
}

output "func_service_plan_id" {
  value = azurerm_service_plan.func.id
}

output "func_storage_account_id" {
  value = azurerm_storage_account.funcsa.id
}

# All resource IDs for bulk assertion in the integration test.
# Excludes the subnet (child resource) since ARG may not list it as top-level.
output "all_resource_ids" {
  value = [
    azurerm_resource_group.test.id,
    azurerm_resource_group.func.id,
    azurerm_virtual_network.test.id,
    azurerm_network_security_group.test.id,
    azurerm_storage_account.test.id,
    azurerm_key_vault.test.id,
    azurerm_log_analytics_workspace.test.id,
    azurerm_container_registry.test.id,
    azurerm_data_factory.test.id,
    azurerm_eventgrid_topic.test.id,
    azurerm_servicebus_namespace.test.id,
    azurerm_linux_web_app.test.id,
    azurerm_linux_function_app.test.id,
    azurerm_automation_account.test.id,
    azurerm_mssql_server.test.id,
    azurerm_linux_virtual_machine.test.id,
    azurerm_network_interface.test.id,
    azurerm_service_plan.test.id,
    azurerm_service_plan.func.id,
    azurerm_storage_account.funcsa.id,
  ]
}
