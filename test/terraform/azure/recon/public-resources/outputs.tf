output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "resource_group_name" {
  value = azurerm_resource_group.test.name
}

output "storage_account_id" {
  value = azurerm_storage_account.public.id
}

output "storage_account_name" {
  value = azurerm_storage_account.public.name
}

output "sql_server_id" {
  value = azurerm_mssql_server.public.id
}

output "sql_server_name" {
  value = azurerm_mssql_server.public.name
}
