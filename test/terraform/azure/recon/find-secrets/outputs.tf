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

output "container_instance_id" {
  value = azurerm_container_group.test.id
}

output "app_config_id" {
  value = azurerm_app_configuration.test.id
}

output "logic_app_id" {
  value = azurerm_logic_app_workflow.test.id
}

output "data_factory_id" {
  value = azurerm_data_factory.test.id
}

output "function_app_id" {
  value = azurerm_linux_function_app.test.id
}

output "web_app_slot_id" {
  value = azurerm_linux_web_app_slot.staging.id
}

output "policy_definition_id" {
  value = azurerm_policy_definition.test.id
}

output "arm_deployment_id" {
  value = azurerm_resource_group_template_deployment.test.id
}

output "template_spec_id" {
  value = azapi_resource.template_spec.id
}

output "vmss_id" {
  value = azurerm_linux_virtual_machine_scale_set.test.id
}

output "container_app_id" {
  value = azurerm_container_app.test.id
}

output "static_web_app_id" {
  value = azurerm_static_web_app.test.id
}

output "app_insights_id" {
  value = azurerm_application_insights.test.id
}

output "batch_account_id" {
  value = azurerm_batch_account.test.id
}

output "acr_id" {
  value = azurerm_container_registry.test.id
}

output "cosmos_account_id" {
  value = azurerm_cosmosdb_account.test.id
}

output "digital_twins_id" {
  value = azurerm_digital_twins_instance.test.id
}

output "synapse_workspace_id" {
  value = azurerm_synapse_workspace.test.id
}

output "apim_id" {
  value = azurerm_api_management.test.id
}
