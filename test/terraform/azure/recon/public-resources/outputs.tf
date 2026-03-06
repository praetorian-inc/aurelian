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

output "postgresql_server_id" {
  value = azurerm_postgresql_flexible_server.public.id
}

output "cognitive_account_id" {
  value = azurerm_cognitive_account.public.id
}

output "search_service_id" {
  value = azurerm_search_service.public.id
}

output "iot_hub_id" {
  value = azurerm_iothub.public.id
}

output "event_grid_topic_id" {
  value = azurerm_eventgrid_topic.public.id
}

output "notification_hub_namespace_id" {
  value = azurerm_notification_hub_namespace.public.id
}

output "app_configuration_id" {
  value = azurerm_app_configuration.public.id
}

output "container_instance_id" {
  value = azurerm_container_group.public.id
}

output "databricks_workspace_id" {
  value = azurerm_databricks_workspace.public.id
}

output "synapse_workspace_id" {
  value = azurerm_synapse_workspace.public.id
}

output "ml_workspace_id" {
  value = azurerm_machine_learning_workspace.public.id
}

output "container_app_id" {
  value = azurerm_container_app.public.id
}

output "logic_app_id" {
  value = azurerm_logic_app_workflow.public.id
}

output "data_factory_id" {
  value = azurerm_data_factory.public.id
}

output "log_analytics_id" {
  value = azurerm_log_analytics_workspace.public.id
}

output "cosmos_db_id" {
  value = azurerm_cosmosdb_account.public.id
}

output "service_bus_id" {
  value = azurerm_servicebus_namespace.public.id
}

output "event_hub_id" {
  value = azurerm_eventhub_namespace.public.id
}

output "redis_cache_id" {
  value = azurerm_redis_cache.public.id
}

output "acr_anon_pull_id" {
  value = azurerm_container_registry.anon_pull.id
}

output "aks_id" {
  value = azurerm_kubernetes_cluster.public.id
}

output "api_management_id" {
  value = azurerm_api_management.public.id
}

output "load_balancer_id" {
  value = azurerm_lb.public.id
}

output "virtual_machine_id" {
  value = azurerm_linux_virtual_machine.public.id
}

output "application_gateway_id" {
  value = azurerm_application_gateway.public.id
}

output "kusto_cluster_id" {
  value = azurerm_kusto_cluster.public.id
}
