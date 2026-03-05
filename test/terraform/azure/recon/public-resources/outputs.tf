# Always available (no tier guard)

output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

# ============================================================================
# TIER 1: MySQL + PostgreSQL Flexible Servers
# ============================================================================

output "mysql_public_id" {
  value = var.enable_tier1 ? azurerm_mysql_flexible_server.public[0].id : ""
}

output "mysql_private_id" {
  value = var.enable_tier1 ? azurerm_mysql_flexible_server.private[0].id : ""
}

output "postgresql_public_id" {
  value = var.enable_tier1 ? azurerm_postgresql_flexible_server.public[0].id : ""
}

output "postgresql_private_id" {
  value = var.enable_tier1 ? azurerm_postgresql_flexible_server.private[0].id : ""
}

# ============================================================================
# TIER 2: Cognitive Services, Search Service, Function Apps
# ============================================================================

output "cognitive_services_public_id" {
  value = var.enable_tier2 ? azurerm_cognitive_account.public[0].id : ""
}

output "cognitive_services_private_id" {
  value = var.enable_tier2 ? azurerm_cognitive_account.private[0].id : ""
}

output "search_service_public_id" {
  value = var.enable_tier2 ? azurerm_search_service.public[0].id : ""
}

output "search_service_private_id" {
  value = var.enable_tier2 ? azurerm_search_service.private[0].id : ""
}

output "function_app_public_id" {
  value = var.enable_tier2 ? azurerm_linux_function_app.public[0].id : ""
}

output "function_app_private_id" {
  value = var.enable_tier2 ? azurerm_linux_function_app.private[0].id : ""
}

# ============================================================================
# TIER 3: IoT Hub, Event Grid Topics, Notification Hubs
# ============================================================================

output "iot_hub_public_id" {
  value = var.enable_tier3 ? azurerm_iothub.public[0].id : ""
}

output "iot_hub_private_id" {
  value = var.enable_tier3 ? azurerm_iothub.private[0].id : ""
}

output "event_grid_topic_public_id" {
  value = var.enable_tier3 ? azurerm_eventgrid_topic.public[0].id : ""
}

output "event_grid_topic_private_id" {
  value = var.enable_tier3 ? azurerm_eventgrid_topic.private[0].id : ""
}

output "notification_hub_public_id" {
  value = var.enable_tier3 ? azurerm_notification_hub_namespace.public[0].id : ""
}

# ============================================================================
# TIER 4A: App Configuration, Data Explorer, Container Instances, Databricks
# ============================================================================

output "app_configuration_public_id" {
  value = var.enable_tier4a ? azurerm_app_configuration.public[0].id : ""
}

output "app_configuration_private_id" {
  value = var.enable_tier4a ? azurerm_app_configuration.private[0].id : ""
}

output "data_explorer_public_id" {
  value = var.enable_tier4a ? azurerm_kusto_cluster.public[0].id : ""
}

output "data_explorer_private_id" {
  value = var.enable_tier4a ? azurerm_kusto_cluster.private[0].id : ""
}

output "container_instance_public_id" {
  value = var.enable_tier4a ? azurerm_container_group.public[0].id : ""
}

output "container_instance_private_id" {
  value = var.enable_tier4a ? azurerm_container_group.private[0].id : ""
}

output "databricks_public_id" {
  value = var.enable_tier4a ? azurerm_databricks_workspace.public[0].id : ""
}

output "databricks_private_id" {
  value = ""
}

# ============================================================================
# TIER 4B: Synapse Analytics, ML Workspace
# ============================================================================

output "synapse_public_id" {
  value = var.enable_tier4b ? azurerm_synapse_workspace.public[0].id : ""
}

output "synapse_private_id" {
  value = var.enable_tier4b ? azurerm_synapse_workspace.private[0].id : ""
}

output "ml_workspace_public_id" {
  value = var.enable_tier4b ? azurerm_machine_learning_workspace.public[0].id : ""
}

output "ml_workspace_private_id" {
  value = var.enable_tier4b ? azurerm_machine_learning_workspace.private[0].id : ""
}

# ============================================================================
# TIER 4C: Container Apps, Logic Apps, Application Gateway
# ============================================================================

output "container_app_public_id" {
  value = var.enable_tier4c ? azurerm_container_app.public[0].id : ""
}

output "container_app_private_id" {
  value = var.enable_tier4c ? azurerm_container_app.private[0].id : ""
}

output "logic_app_public_id" {
  value = var.enable_tier4c ? azurerm_logic_app_workflow.public[0].id : ""
}

output "logic_app_private_id" {
  value = var.enable_tier4c ? azurerm_logic_app_workflow.private[0].id : ""
}

output "application_gateway_public_id" {
  value = var.enable_tier4c ? azurerm_application_gateway.public[0].id : ""
}

# ============================================================================
# TIER 5A: Storage, Key Vault, App Service, Data Factory, Log Analytics, ACR
# ============================================================================

output "storage_account_public_id" {
  value = var.enable_tier5a ? azurerm_storage_account.public[0].id : ""
}

output "storage_account_private_id" {
  value = var.enable_tier5a ? azurerm_storage_account.private[0].id : ""
}

output "key_vault_public_id" {
  value = var.enable_tier5a ? azurerm_key_vault.public[0].id : ""
}

output "key_vault_private_id" {
  value = var.enable_tier5a ? azurerm_key_vault.private[0].id : ""
}

output "app_service_public_id" {
  value = var.enable_tier5a ? azurerm_linux_web_app.public[0].id : ""
}

output "app_service_private_id" {
  value = var.enable_tier5a ? azurerm_linux_web_app.private[0].id : ""
}

output "data_factory_public_id" {
  value = var.enable_tier5a ? azurerm_data_factory.public[0].id : ""
}

output "data_factory_private_id" {
  value = var.enable_tier5a ? azurerm_data_factory.private[0].id : ""
}

output "log_analytics_public_id" {
  value = var.enable_tier5a ? azurerm_log_analytics_workspace.public[0].id : ""
}

output "log_analytics_private_id" {
  value = var.enable_tier5a ? azurerm_log_analytics_workspace.private[0].id : ""
}

output "container_registry_public_id" {
  value = var.enable_tier5a ? azurerm_container_registry.public[0].id : ""
}

output "container_registry_private_id" {
  value = var.enable_tier5a ? azurerm_container_registry.private[0].id : ""
}

# ============================================================================
# TIER 5B: SQL Server, Cosmos DB, Service Bus, Event Hub, Redis Cache, ACR Anon
# ============================================================================

output "sql_server_public_id" {
  value = var.enable_tier5b ? azurerm_mssql_server.public[0].id : ""
}

output "sql_server_private_id" {
  value = var.enable_tier5b ? azurerm_mssql_server.private[0].id : ""
}

output "cosmos_db_public_id" {
  value = var.enable_tier5b ? azurerm_cosmosdb_account.public[0].id : ""
}

output "cosmos_db_private_id" {
  value = var.enable_tier5b ? azurerm_cosmosdb_account.private[0].id : ""
}

output "service_bus_public_id" {
  value = var.enable_tier5b ? azurerm_servicebus_namespace.public[0].id : ""
}

output "event_hub_public_id" {
  value = var.enable_tier5b ? azurerm_eventhub_namespace.public[0].id : ""
}

output "event_hub_private_id" {
  value = var.enable_tier5b ? azurerm_eventhub_namespace.private[0].id : ""
}

output "redis_cache_public_id" {
  value = var.enable_tier5b ? azurerm_redis_cache.public[0].id : ""
}

output "redis_cache_private_id" {
  value = var.enable_tier5b ? azurerm_redis_cache.private[0].id : ""
}

output "acr_anon_pull_id" {
  value = var.enable_tier5b ? azurerm_container_registry.anon_pull[0].id : ""
}

output "acr_anon_pull_disabled_id" {
  value = var.enable_tier5b ? azurerm_container_registry.anon_pull_disabled[0].id : ""
}

# ============================================================================
# TIER 5C: AKS, API Management, Load Balancer, Virtual Machine
# ============================================================================

output "aks_public_id" {
  value = var.enable_tier5c ? azurerm_kubernetes_cluster.public[0].id : ""
}

output "aks_private_id" {
  value = var.enable_tier5c ? azurerm_kubernetes_cluster.private[0].id : ""
}

output "api_management_public_id" {
  value = var.enable_tier5c ? azurerm_api_management.public[0].id : ""
}

output "load_balancer_public_id" {
  value = var.enable_tier5c ? azurerm_lb.public[0].id : ""
}

output "load_balancer_private_id" {
  value = var.enable_tier5c ? azurerm_lb.private[0].id : ""
}

output "virtual_machine_public_id" {
  value = var.enable_tier5c ? azurerm_linux_virtual_machine.public[0].id : ""
}

output "virtual_machine_private_id" {
  value = var.enable_tier5c ? azurerm_linux_virtual_machine.private[0].id : ""
}
