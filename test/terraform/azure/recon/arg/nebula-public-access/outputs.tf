# Consolidated Outputs for Nebula Azure Public Access Testing Infrastructure

output "resource_group_name" {
  description = "Name of the resource group containing all test resources"
  value       = azurerm_resource_group.main.name
}

output "subscription_id" {
  description = "Azure subscription ID (for Nebula scan command)"
  value       = data.azurerm_client_config.current.subscription_id
}

output "location" {
  description = "Azure region where resources are deployed"
  value       = azurerm_resource_group.main.location
}

# ============================================================================
# TIER STATUS
# ============================================================================

output "enabled_tiers" {
  description = "Which tiers are enabled"
  value = {
    tier1  = var.enable_tier1
    tier2  = var.enable_tier2
    tier3  = var.enable_tier3
    tier4a = var.enable_tier4a
    tier4b = var.enable_tier4b
    tier4c = var.enable_tier4c
    tier5a = var.enable_tier5a
    tier5b = var.enable_tier5b
    tier5c = var.enable_tier5c
  }
}

# ============================================================================
# DETECTION SUMMARY
# ============================================================================

output "test_summary" {
  description = "Summary of deployed resources and expected detection results"
  value = {
    resource_group = azurerm_resource_group.main.name
    location       = azurerm_resource_group.main.location

    public_resources = merge(
      var.enable_tier1 ? {
        mysql_public      = azurerm_mysql_flexible_server.public[0].name
        postgresql_public = azurerm_postgresql_flexible_server.public[0].name
      } : {},
      var.enable_tier2 ? {
        cognitive_services_public = azurerm_cognitive_account.public[0].name
        search_service_public     = azurerm_search_service.public[0].name
        function_app_public       = azurerm_linux_function_app.public[0].name
      } : {},
      var.enable_tier3 ? {
        iot_hub_public          = azurerm_iothub.public[0].name
        event_grid_topic_public = azurerm_eventgrid_topic.public[0].name
        notification_hub_public = azurerm_notification_hub_namespace.public[0].name
      } : {},
      var.enable_tier4a ? {
        app_configuration_public  = azurerm_app_configuration.public[0].name
        data_explorer_public      = azurerm_kusto_cluster.public[0].name
        container_instance_public = azurerm_container_group.public[0].name
        databricks_public         = azurerm_databricks_workspace.public[0].name
      } : {},
      var.enable_tier4b ? {
        synapse_public      = azurerm_synapse_workspace.public[0].name
        ml_workspace_public = azurerm_machine_learning_workspace.public[0].name
      } : {},
      var.enable_tier4c ? {
        container_app_public = azurerm_container_app.public[0].name
        logic_app_public     = azurerm_logic_app_workflow.public[0].name
        appgw_public         = azurerm_application_gateway.public[0].name
      } : {},
      var.enable_tier5a ? {
        storage_account_public    = azurerm_storage_account.public[0].name
        key_vault_public          = azurerm_key_vault.public[0].name
        app_service_public        = azurerm_linux_web_app.public[0].name
        data_factory_public       = azurerm_data_factory.public[0].name
        log_analytics_public      = azurerm_log_analytics_workspace.public[0].name
        container_registry_public = azurerm_container_registry.public[0].name
      } : {},
      var.enable_tier5b ? {
        sql_server_public  = azurerm_mssql_server.public[0].name
        cosmos_db_public   = azurerm_cosmosdb_account.public[0].name
        service_bus_public = azurerm_servicebus_namespace.public[0].name
        event_hub_public   = azurerm_eventhub_namespace.public[0].name
        redis_cache_public = azurerm_redis_cache.public[0].name
        acr_anon_pull      = azurerm_container_registry.anon_pull[0].name
      } : {},
      var.enable_tier5c ? {
        aks_public             = azurerm_kubernetes_cluster.public[0].name
        api_management_public  = azurerm_api_management.public[0].name
        load_balancer_public   = azurerm_lb.public[0].name
        virtual_machine_public = azurerm_linux_virtual_machine.public[0].name
      } : {},
    )

    private_resources = merge(
      var.enable_tier1 ? {
        mysql_private      = azurerm_mysql_flexible_server.private[0].name
        postgresql_private = azurerm_postgresql_flexible_server.private[0].name
      } : {},
      var.enable_tier2 ? {
        cognitive_services_private = azurerm_cognitive_account.private[0].name
        search_service_private     = azurerm_search_service.private[0].name
        function_app_private       = azurerm_linux_function_app.private[0].name
      } : {},
      var.enable_tier3 ? {
        event_grid_topic_private = azurerm_eventgrid_topic.private[0].name
        iot_hub_private          = azurerm_iothub.private[0].name
      } : {},
      var.enable_tier4a ? {
        app_configuration_private  = azurerm_app_configuration.private[0].name
        container_instance_private = azurerm_container_group.private[0].name
        data_explorer_private      = azurerm_kusto_cluster.private[0].name
        databricks_private         = azurerm_databricks_workspace.private[0].name
      } : {},
      var.enable_tier4b ? {
        synapse_private      = azurerm_synapse_workspace.private[0].name
        ml_workspace_private = azurerm_machine_learning_workspace.private[0].name
      } : {},
      var.enable_tier4c ? {
        logic_app_private     = azurerm_logic_app_workflow.private[0].name
        container_app_private = azurerm_container_app.private[0].name
      } : {},
      var.enable_tier5a ? {
        storage_account_private    = azurerm_storage_account.private[0].name
        key_vault_private          = azurerm_key_vault.private[0].name
        app_service_private        = azurerm_linux_web_app.private[0].name
        data_factory_private       = azurerm_data_factory.private[0].name
        log_analytics_private      = azurerm_log_analytics_workspace.private[0].name
        container_registry_private = azurerm_container_registry.private[0].name
      } : {},
      var.enable_tier5b ? {
        sql_server_private     = azurerm_mssql_server.private[0].name
        cosmos_db_private      = azurerm_cosmosdb_account.private[0].name
        event_hub_private      = azurerm_eventhub_namespace.private[0].name
        redis_cache_private    = azurerm_redis_cache.private[0].name
        acr_anon_pull_disabled = azurerm_container_registry.anon_pull_disabled[0].name
      } : {},
      var.enable_tier5c ? {
        aks_private             = azurerm_kubernetes_cluster.private[0].name
        load_balancer_private   = azurerm_lb.private[0].name
        virtual_machine_private = azurerm_linux_virtual_machine.private[0].name
      } : {},
    )

    expected_detections = (
      (var.enable_tier1 ? 2 : 0) +
      (var.enable_tier2 ? 3 : 0) +
      (var.enable_tier3 ? 3 : 0) +
      (var.enable_tier4a ? 4 : 0) +
      (var.enable_tier4b ? 2 : 0) +
      (var.enable_tier4c ? 3 : 0) +
      (var.enable_tier5a ? 6 : 0) +
      (var.enable_tier5b ? 6 : 0) +
      (var.enable_tier5c ? 4 : 0)
    )

    expected_non_detections = (
      (var.enable_tier1 ? 2 : 0) +
      (var.enable_tier2 ? 3 : 0) +
      (var.enable_tier3 ? 2 : 0) +
      (var.enable_tier4a ? 4 : 0) +
      (var.enable_tier4b ? 2 : 0) +
      (var.enable_tier4c ? 2 : 0) +
      (var.enable_tier5a ? 6 : 0) +
      (var.enable_tier5b ? 5 : 0) +
      (var.enable_tier5c ? 3 : 0)
    )
  }
}

# ============================================================================
# TEST COMMANDS
# ============================================================================

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA PUBLIC ACCESS TESTING INFRASTRUCTURE
    ============================================

    Resource Group: ${azurerm_resource_group.main.name}
    Location: ${azurerm_resource_group.main.location}
    Subscription: ${data.azurerm_client_config.current.subscription_id}

    Enabled Tiers:
      Tier 1  (MySQL/PostgreSQL):       ${var.enable_tier1}
      Tier 2  (Cognitive/Search/Func):  ${var.enable_tier2}
      Tier 3  (IoT/EventGrid/NH):      ${var.enable_tier3}
      Tier 4A (AppConfig/Kusto/ACI):    ${var.enable_tier4a}
      Tier 4B (Synapse/ML):            ${var.enable_tier4b}
      Tier 4C (ContainerApp/Logic/AGW): ${var.enable_tier4c}
      Tier 5A (Storage/KV/App/ADF/LA):  ${var.enable_tier5a}
      Tier 5B (SQL/Cosmos/SB/EH/Redis): ${var.enable_tier5b}
      Tier 5C (AKS/APIM/LB/VM):        ${var.enable_tier5c}

    ============================================
    WAIT: Azure Resource Graph needs 5-10 min
    to index newly created resources.
    ============================================

    1. Navigate to Nebula directory:
       cd /Users/weililiow/Documents/tools/nebula

    2. Run Nebula scan:
       go run . azure recon arg-scan \
         -s ${data.azurerm_client_config.current.subscription_id} \
         -c "Public Access" \
         -o /tmp/nebula-public-access-scan/

    3. Count detected findings:
       cat /tmp/nebula-public-access-scan/*.json | jq '.findings | length'

    4. Check for false positives (private resources):
       cat /tmp/nebula-public-access-scan/*.json | jq '.findings[] | select(.name | contains("prv"))'
       # Expected: Empty (no private resources detected)

    ============================================
    CLEANUP
    ============================================

    terraform destroy -auto-approve

    Or via Azure CLI (faster, avoids state issues):
    az group delete --name ${azurerm_resource_group.main.name} --yes --no-wait
  EOT
}
