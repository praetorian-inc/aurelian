output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "storage_account_id" {
  value = azurerm_storage_account.public.id
}

output "key_vault_id" {
  value = azurerm_key_vault.public.id
}

output "sql_server_id" {
  value = azurerm_mssql_server.public.id
}

output "acr_id" {
  value = azurerm_container_registry.public.id
}
