// Module: azure-recon-public-resources
// Provisions intentionally public Azure resources for testing the
// azure/recon/public-resources module, which uses ARG query templates
// to detect publicly accessible resources.
//
// Adapted from Nebula's nebula-public-access testing infrastructure.
//
// Resources that hit quota/provider limits in eastus2 are deployed to a
// secondary region (westus2 by default): SQL Server, Synapse, ML Workspace,
// Container App. Azure ARG queries work cross-region within a subscription.
//
// ==================== TEST CASES ====================
//
// | #  | Resource                     | Template ID                                | Expected |
// |----|------------------------------|--------------------------------------------|----------|
// | 1  | Storage Account              | storage_accounts_public                    | DETECTED |
// | 2  | Key Vault                    | key_vault_public_access                    | DETECTED |
// | 3  | SQL Server                   | sql_servers_public                         | DETECTED |
// | 4  | Container Registry           | container_registries_public                | DETECTED |
// | 5  | MySQL Flexible Server        | mysql_flexible_server_public_access        | DETECTED |
// | 6  | PostgreSQL Flexible Server   | postgresql_flexible_server_public_access   | DETECTED |
// | 7  | Cognitive Services           | cognitive_services_public_access           | DETECTED |
// | 8  | Search Service               | search_service_public_access               | DETECTED |
// | 9  | Function App                 | function_apps_public_http_triggers         | DETECTED |
// | 10 | IoT Hub                      | iot_hub_public_access                      | DETECTED |
// | 11 | Event Grid Topic             | event_grid_topics_public_access            | DETECTED |
// | 12 | Notification Hub             | notification_hubs_public_access            | DETECTED |
// | 13 | App Configuration            | app_configuration_public_access            | DETECTED |
// | 14 | Container Instance           | container_instances_public_access          | DETECTED |
// | 15 | Databricks                   | databricks_public_access                   | DETECTED |
// | 16 | Synapse Analytics            | synapse_public_access                      | DETECTED |
// | 17 | ML Workspace                 | ml_workspace_public_access                 | DETECTED |
// | 18 | Container App                | container_apps_public_access               | DETECTED |
// | 19 | Logic App                    | logic_apps_public_access                   | DETECTED |
// | 20 | App Service                  | app_services_public                        | DETECTED |
// | 21 | Data Factory                 | data_factory_public                        | DETECTED |
// | 22 | Log Analytics                | log_analytics_public                       | DETECTED |
// | 23 | Cosmos DB                    | cosmos_db_public                           | DETECTED |
// | 24 | Service Bus                  | service_bus_public                         | DETECTED |
// | 25 | Event Hub                    | event_hub_public                           | DETECTED |
// | 26 | Redis Cache                  | redis_cache_public                         | DETECTED |
// | 27 | ACR Anonymous Pull           | acr_anonymous_pull                         | DETECTED |
// | 28 | AKS                          | aks_public_access                          | DETECTED |
// | 29 | API Management               | api_management_public_access               | DETECTED |
// | 30 | Load Balancer                | load_balancers_public                      | DETECTED |
// | 31 | Virtual Machine              | virtual_machines_public                    | DETECTED |
// | 32 | Application Gateway          | application_gateway_public_access          | DETECTED |
// | 33 | Data Explorer (Kusto)        | data_explorer_public_access                | DETECTED |

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "s3" {}
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "random_password" "db" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

locals {
  prefix     = "aur-pub-${random_string.suffix.result}"
  prefix_san = "aurpub${random_string.suffix.result}"
  location   = var.location
  tags = {
    ManagedBy = "terraform"
    Purpose   = "aurelian-public-resources-testing"
  }
}

variable "location" {
  description = "Azure region for test resources"
  type        = string
  default     = "eastus2"
}

variable "location_secondary" {
  description = "Secondary Azure region for resources that hit quota/provider limits in the primary region"
  type        = string
  default     = "westus2"
}

# ============================================================================
# Resource Group
# ============================================================================

resource "azurerm_resource_group" "test" {
  name     = "${local.prefix}-rg"
  location = local.location
  tags     = local.tags
}

# ============================================================================
# Shared Networking
# ============================================================================

resource "azurerm_virtual_network" "main" {
  name                = "${local.prefix}-vnet"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  address_space       = ["10.0.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "appgw" {
  name                 = "appgw-subnet"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.4.0/24"]
}

resource "azurerm_subnet" "vm" {
  name                 = "vm-subnet"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.5.0/24"]
}

# ============================================================================
# 1. Storage Account — publicly accessible
# ============================================================================

resource "azurerm_storage_account" "public" {
  name                            = "${local.prefix_san}sa"
  resource_group_name             = azurerm_resource_group.test.name
  location                        = local.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  public_network_access_enabled   = true
  allow_nested_items_to_be_public = true

  network_rules {
    default_action = "Allow"
  }

  tags = local.tags
}

# ============================================================================
# 2. Key Vault — publicly accessible
# ============================================================================

resource "azurerm_key_vault" "public" {
  name                          = "${local.prefix}-kv"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  purge_protection_enabled      = false
  soft_delete_retention_days    = 7
  public_network_access_enabled = true

  network_acls {
    default_action = "Allow"
    bypass         = "None"
  }

  tags = local.tags
}

# ============================================================================
# 3. SQL Server — publicly accessible
# ============================================================================

resource "azurerm_mssql_server" "public" {
  name                          = "${local.prefix}-w-sql"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = var.location_secondary
  version                       = "12.0"
  administrator_login           = "aurelianadmin"
  administrator_login_password  = "P@ssw0rd${random_string.suffix.result}!"
  public_network_access_enabled = true
  tags                          = local.tags
}

# ============================================================================
# 4. Container Registry — publicly accessible (admin enabled)
# ============================================================================

resource "azurerm_container_registry" "public" {
  name                          = "${local.prefix_san}acr"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  sku                           = "Basic"
  admin_enabled                 = true
  public_network_access_enabled = true
  tags                          = local.tags
}

# ============================================================================
# 5. PostgreSQL Flexible Server — publicly accessible
# ============================================================================

resource "azurerm_postgresql_flexible_server" "public" {
  name                   = "${local.prefix}-pg"
  resource_group_name    = azurerm_resource_group.test.name
  location               = local.location
  administrator_login    = "pgadmin"
  administrator_password = random_password.db.result
  sku_name               = "B_Standard_B1ms"
  version                = "16"
  tags                   = local.tags

  lifecycle { ignore_changes = [zone] }
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_all" {
  name             = "AllowAll"
  server_id        = azurerm_postgresql_flexible_server.public.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

# ============================================================================
# 7. Cognitive Services — publicly accessible
# ============================================================================

resource "azurerm_cognitive_account" "public" {
  name                          = "${local.prefix}-cog"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  kind                          = "TextAnalytics"
  sku_name                      = "S"
  custom_subdomain_name         = "${local.prefix}-cog"
  public_network_access_enabled = true

  network_acls { default_action = "Allow" }

  tags = local.tags
}

# ============================================================================
# 8. Search Service — publicly accessible
# ============================================================================

resource "azurerm_search_service" "public" {
  name                          = "${local.prefix}-search"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  sku                           = "free"
  public_network_access_enabled = true
  tags                          = local.tags
}

# ============================================================================
# 9. IoT Hub — publicly accessible
# ============================================================================

resource "azurerm_iothub" "public" {
  name                          = "${local.prefix}-iot"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  public_network_access_enabled = true

  sku {
    name     = "B1"
    capacity = 1
  }

  tags = local.tags
}

# ============================================================================
# 11. Event Grid Topic — publicly accessible
# ============================================================================

resource "azurerm_eventgrid_topic" "public" {
  name                          = "${local.prefix}-egt"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  public_network_access_enabled = true
  tags                          = local.tags
}

# ============================================================================
# 12. Notification Hub Namespace — publicly accessible
# ============================================================================

resource "azurerm_notification_hub_namespace" "public" {
  name                = "${local.prefix}-nhns"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  namespace_type      = "NotificationHub"
  sku_name            = "Free"
  tags                = local.tags
}

# ============================================================================
# 13. App Configuration — publicly accessible
# ============================================================================

resource "azurerm_app_configuration" "public" {
  name                  = "${local.prefix}-appconf"
  resource_group_name   = azurerm_resource_group.test.name
  location              = local.location
  sku                   = "free"
  public_network_access = "Enabled"
  tags                  = local.tags
}

# ============================================================================
# 14. Container Instance — publicly accessible
# ============================================================================

resource "azurerm_container_group" "public" {
  name                = "${local.prefix}-ci"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  os_type             = "Linux"
  ip_address_type     = "Public"

  container {
    name   = "hello"
    image  = "mcr.microsoft.com/azuredocs/aci-helloworld:latest"
    cpu    = "0.5"
    memory = "0.5"
    ports {
      port     = 80
      protocol = "TCP"
    }
  }

  tags = local.tags
}

# ============================================================================
# 15. Databricks — publicly accessible
# ============================================================================

resource "azurerm_databricks_workspace" "public" {
  name                          = "${local.prefix}-dbw"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  sku                           = "trial"
  public_network_access_enabled = true
  tags                          = local.tags
}

# ============================================================================
# 16. Synapse Analytics — publicly accessible
# ============================================================================

resource "azurerm_storage_account" "synapse" {
  name                     = "${local.prefix_san}wsyn"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = var.location_secondary
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  is_hns_enabled           = true
  tags                     = local.tags
}

resource "azurerm_storage_data_lake_gen2_filesystem" "synapse" {
  name               = "synapsefs"
  storage_account_id = azurerm_storage_account.synapse.id
}

resource "azurerm_synapse_workspace" "public" {
  name                                 = "${local.prefix}-w-syn"
  resource_group_name                  = azurerm_resource_group.test.name
  location                             = var.location_secondary
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.synapse.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = "P@ssw0rd1234!"
  public_network_access_enabled        = true

  identity { type = "SystemAssigned" }

  tags = local.tags
}

# ============================================================================
# 17. ML Workspace — publicly accessible
# ============================================================================

resource "azurerm_storage_account" "ml" {
  name                     = "${local.prefix_san}wml"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = var.location_secondary
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

resource "azurerm_key_vault" "ml" {
  name                = "${local.prefix}-wmlkv"
  resource_group_name = azurerm_resource_group.test.name
  location            = var.location_secondary
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
  tags                = local.tags
}

resource "azurerm_log_analytics_workspace" "ml" {
  name                = "${local.prefix}-wmllaw"
  resource_group_name = azurerm_resource_group.test.name
  location            = var.location_secondary
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

resource "azurerm_application_insights" "ml" {
  name                = "${local.prefix}-wmlai"
  resource_group_name = azurerm_resource_group.test.name
  location            = var.location_secondary
  application_type    = "web"
  workspace_id        = azurerm_log_analytics_workspace.ml.id
  tags                = local.tags
}

resource "azurerm_machine_learning_workspace" "public" {
  name                          = "${local.prefix}-w-mlw"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = var.location_secondary
  application_insights_id       = azurerm_application_insights.ml.id
  key_vault_id                  = azurerm_key_vault.ml.id
  storage_account_id            = azurerm_storage_account.ml.id
  public_network_access_enabled = true

  identity { type = "SystemAssigned" }

  tags = local.tags
}

# ============================================================================
# 18. Container App — publicly accessible (external ingress)
# ============================================================================

resource "azurerm_log_analytics_workspace" "containerapp" {
  name                = "${local.prefix}-wcalaw"
  resource_group_name = azurerm_resource_group.test.name
  location            = var.location_secondary
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

resource "azurerm_container_app_environment" "main" {
  name                       = "${local.prefix}-w-cae"
  resource_group_name        = azurerm_resource_group.test.name
  location                   = var.location_secondary
  log_analytics_workspace_id = azurerm_log_analytics_workspace.containerapp.id
  tags                       = local.tags
}

resource "azurerm_container_app" "public" {
  name                         = "${local.prefix}-w-ca"
  resource_group_name          = azurerm_resource_group.test.name
  container_app_environment_id = azurerm_container_app_environment.main.id
  revision_mode                = "Single"

  template {
    container {
      name   = "hello"
      image  = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"
      cpu    = 0.25
      memory = "0.5Gi"
    }
  }

  ingress {
    external_enabled = true
    target_port      = 80
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  tags = local.tags
}

# ============================================================================
# 19. Logic App — publicly accessible (no access control)
# ============================================================================

resource "azurerm_logic_app_workflow" "public" {
  name                = "${local.prefix}-la"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  tags                = local.tags
}

# ============================================================================
# 20. Data Factory — publicly accessible
# ============================================================================

resource "azurerm_data_factory" "public" {
  name                   = "${local.prefix}-adf"
  resource_group_name    = azurerm_resource_group.test.name
  location               = local.location
  public_network_enabled = true
  tags                   = local.tags
}

# ============================================================================
# 22. Log Analytics Workspace — publicly accessible
# ============================================================================

resource "azurerm_log_analytics_workspace" "public" {
  name                       = "${local.prefix}-law"
  resource_group_name        = azurerm_resource_group.test.name
  location                   = local.location
  sku                        = "PerGB2018"
  retention_in_days          = 30
  internet_ingestion_enabled = true
  internet_query_enabled     = true
  tags                       = local.tags
}

# ============================================================================
# 23. Cosmos DB — publicly accessible
# ============================================================================

resource "azurerm_cosmosdb_account" "public" {
  name                          = "${local.prefix}-cosmos"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  public_network_access_enabled = true

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = local.location
    failover_priority = 0
  }

  tags = local.tags
}

# ============================================================================
# 24. Service Bus — publicly accessible
# ============================================================================

resource "azurerm_servicebus_namespace" "public" {
  name                = "${local.prefix}-sbus"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  sku                 = "Basic"
  tags                = local.tags
}

# ============================================================================
# 25. Event Hub — publicly accessible
# ============================================================================

resource "azurerm_eventhub_namespace" "public" {
  name                = "${local.prefix}-eh"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  sku                 = "Basic"
  tags                = local.tags
}

# ============================================================================
# 26. Redis Cache — publicly accessible
# ============================================================================

resource "azurerm_redis_cache" "public" {
  name                          = "${local.prefix}-redis"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  capacity                      = 0
  family                        = "C"
  sku_name                      = "Basic"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = true

  redis_configuration {}

  tags = local.tags
}

# ============================================================================
# 27. ACR with Anonymous Pull — publicly accessible
# ============================================================================

resource "azurerm_container_registry" "anon_pull" {
  name                          = "${local.prefix_san}acranon"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  sku                           = "Standard"
  public_network_access_enabled = true
  admin_enabled                 = false
  anonymous_pull_enabled        = true
  tags                          = local.tags
}

# ============================================================================
# 28. AKS — publicly accessible (non-private cluster)
# ============================================================================

resource "azurerm_kubernetes_cluster" "public" {
  name                = "${local.prefix}-aks"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  dns_prefix          = "${local.prefix}-aks"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_B2s"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

# ============================================================================
# 29. API Management — publicly accessible
# ============================================================================

resource "azurerm_api_management" "public" {
  name                = "${local.prefix}-apim"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  publisher_name      = "Aurelian Testing"
  publisher_email     = "aurelian-test@example.com"
  sku_name            = "Consumption_0"
  tags                = local.tags
}

# ============================================================================
# 30. Load Balancer — publicly accessible
# ============================================================================

resource "azurerm_public_ip" "lb" {
  name                = "${local.prefix}-lb-pip"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_lb" "public" {
  name                = "${local.prefix}-lb"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  sku                 = "Standard"

  frontend_ip_configuration {
    name                 = "public-frontend"
    public_ip_address_id = azurerm_public_ip.lb.id
  }

  tags = local.tags
}

# ============================================================================
# 31. Virtual Machine — publicly accessible (public IP + open NSG)
# ============================================================================

resource "azurerm_network_security_group" "vm_public" {
  name                = "${local.prefix}-nsg"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location

  security_rule {
    name                       = "AllowHTTPInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.tags
}

resource "azurerm_public_ip" "vm" {
  name                = "${local.prefix}-vm-pip"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "vm_public" {
  name                = "${local.prefix}-nic"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vm.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }

  tags = local.tags
}

resource "azurerm_network_interface_security_group_association" "vm_public" {
  network_interface_id      = azurerm_network_interface.vm_public.id
  network_security_group_id = azurerm_network_security_group.vm_public.id
}

resource "azurerm_linux_virtual_machine" "public" {
  name                            = "${local.prefix}-vm"
  resource_group_name             = azurerm_resource_group.test.name
  location                        = local.location
  size                            = "Standard_B1ls"
  admin_username                  = "azureuser"
  admin_password                  = random_password.db.result
  disable_password_authentication = false
  network_interface_ids           = [azurerm_network_interface.vm_public.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  tags = local.tags
}

# ============================================================================
# 32. Application Gateway — publicly accessible
# ============================================================================

resource "azurerm_public_ip" "appgw" {
  name                = "${local.prefix}-appgw-pip"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_application_gateway" "public" {
  name                = "${local.prefix}-appgw"
  resource_group_name = azurerm_resource_group.test.name
  location            = local.location

  sku {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 1
  }

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101"
  }

  gateway_ip_configuration {
    name      = "gw-ip-config"
    subnet_id = azurerm_subnet.appgw.id
  }

  frontend_port {
    name = "http-port"
    port = 80
  }

  frontend_ip_configuration {
    name                 = "public-frontend"
    public_ip_address_id = azurerm_public_ip.appgw.id
  }

  backend_address_pool {
    name = "default-pool"
  }

  backend_http_settings {
    name                  = "default-settings"
    cookie_based_affinity = "Disabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 60
  }

  http_listener {
    name                           = "default-listener"
    frontend_ip_configuration_name = "public-frontend"
    frontend_port_name             = "http-port"
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = "default-rule"
    priority                   = 100
    rule_type                  = "Basic"
    http_listener_name         = "default-listener"
    backend_address_pool_name  = "default-pool"
    backend_http_settings_name = "default-settings"
  }

  tags = local.tags
}

# ============================================================================
# 33. Data Explorer (Kusto) — publicly accessible
# Note: Takes ~15 min to provision
# ============================================================================

resource "azurerm_kusto_cluster" "public" {
  name                          = "${local.prefix_san}kusto"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = local.location
  public_network_access_enabled = true

  sku {
    name     = "Dev(No SLA)_Standard_E2a_v4"
    capacity = 1
  }

  tags = local.tags
}
