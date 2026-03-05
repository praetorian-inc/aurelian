output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "resource_group_name" {
  value = azurerm_resource_group.test.name
}

output "vm_id" {
  value = azurerm_linux_virtual_machine.test.id
}

output "web_app_id" {
  value = azurerm_linux_web_app.test.id
}

output "automation_account_id" {
  value = azurerm_automation_account.test.id
}

output "storage_account_id" {
  value = azurerm_storage_account.test.id
}
