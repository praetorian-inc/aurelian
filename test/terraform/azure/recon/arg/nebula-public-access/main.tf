# Nebula Azure Public Access - Consolidated Testing Infrastructure
# Purpose: Deploy all test resources for validating Nebula public access detection
# Usage:  terraform apply                              # Deploy everything
#         terraform apply -var="enable_tier4c=false"    # Skip expensive App Gateway tier
#         terraform destroy -auto-approve               # Tear down everything
#
# Cost estimate (all tiers): ~$1.90/hr (includes TN/private variants)
#   Tier 1:  ~$0.80/hr  (MySQL + PostgreSQL B1 servers, public + private)
#   Tier 2:  ~$0.11/hr  (Cognitive S, Search basic+free, Function Apps consumption)
#   Tier 3:  ~$0.07/hr  (IoT Hub B1 x2, Event Grid free, Notification Hubs free)
#   Tier 4A: ~$0.40/hr  (App Config, Kusto dev x2, Container Instance, Databricks trial+premium)
#   Tier 4B: ~$0.18/hr  (Synapse x2, ML Workspace x2)
#   Tier 4C: ~$0.26/hr  (Container App x2, Logic App, App Gateway Standard_v2)
#   Tier 5A: ~$0.08/hr  (Storage, Key Vault, App Service, Data Factory, Log Analytics, ACR Basic+Premium)
#   Tier 5B: ~$0.14/hr  (SQL Server, Cosmos DB x2, Service Bus, Event Hub x2, Redis C0 x2, ACR Std x2)
#   Tier 5C: ~$0.16/hr  (AKS x2 free+B2s, API Mgmt, Load Balancer x2, VM B1ls x2)

terraform {
  required_version = ">= 1.0"
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
      purge_soft_delete_on_destroy = true
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

locals {
  pfx = "nbpa" # nebula-public-access
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-public-access-testing"
    Environment = "test"
    ManagedBy   = "terraform"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "${local.pfx}-rg-${local.sfx}"
  location = local.loc
  tags     = local.tags
}

# ============================================================================
# SHARED NETWORKING (used by Tier 1, 4A, 4C)
# ============================================================================

resource "azurerm_virtual_network" "main" {
  name                = "${local.pfx}-vnet-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  address_space       = ["10.0.0.0/16"]
  tags                = local.tags
}

# Subnets for private resources
resource "azurerm_subnet" "mysql" {
  count                = var.enable_tier1 ? 1 : 0
  name                 = "mysql-private"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]

  delegation {
    name = "mysql"
    service_delegation {
      name    = "Microsoft.DBforMySQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "postgresql" {
  count                = var.enable_tier1 ? 1 : 0
  name                 = "postgresql-private"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]

  delegation {
    name = "postgresql"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "container" {
  count                = var.enable_tier4a ? 1 : 0
  name                 = "container-private"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.3.0/24"]

  delegation {
    name = "container"
    service_delegation {
      name    = "Microsoft.ContainerInstance/containerGroups"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

resource "azurerm_subnet" "appgw" {
  count                = var.enable_tier4c ? 1 : 0
  name                 = "appgw-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.4.0/24"]
}

# ============================================================================
# TIER 1: MySQL + PostgreSQL Flexible Servers
# ============================================================================

resource "random_password" "db" {
  count            = var.enable_tier1 ? 1 : 0
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# MySQL - Public (SHOULD DETECT)
resource "azurerm_mysql_flexible_server" "public" {
  count                  = var.enable_tier1 ? 1 : 0
  name                   = "${local.pfx}-mysql-pub-${local.sfx}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = local.loc
  administrator_login    = "mysqladmin"
  administrator_password = random_password.db[0].result
  sku_name               = "B_Standard_B1s"

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "MySQL-Public" })
}

resource "azurerm_mysql_flexible_server_firewall_rule" "allow_all" {
  count               = var.enable_tier1 ? 1 : 0
  name                = "AllowAll"
  resource_group_name = azurerm_resource_group.main.name
  server_name         = azurerm_mysql_flexible_server.public[0].name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "255.255.255.255"
}

# MySQL - Private (SHOULD NOT DETECT)
resource "azurerm_mysql_flexible_server" "private" {
  count                  = var.enable_tier1 ? 1 : 0
  name                   = "${local.pfx}-mysql-prv-${local.sfx}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = local.loc
  administrator_login    = "mysqladmin"
  administrator_password = random_password.db[0].result
  sku_name               = "B_Standard_B1s"
  delegated_subnet_id    = azurerm_subnet.mysql[0].id

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "MySQL-Private" })
}

# PostgreSQL - Public (SHOULD DETECT)
resource "azurerm_postgresql_flexible_server" "public" {
  count                  = var.enable_tier1 ? 1 : 0
  name                   = "${local.pfx}-pg-pub-${local.sfx}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = local.loc
  administrator_login    = "pgadmin"
  administrator_password = random_password.db[0].result
  sku_name               = "B_Standard_B1ms"
  version                = "16"

  lifecycle { ignore_changes = [zone] }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "PostgreSQL-Public" })
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_all" {
  count            = var.enable_tier1 ? 1 : 0
  name             = "AllowAll"
  server_id        = azurerm_postgresql_flexible_server.public[0].id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

# PostgreSQL Private DNS Zone (required for VNet-integrated servers)
resource "azurerm_private_dns_zone" "postgresql" {
  count               = var.enable_tier1 ? 1 : 0
  name                = "${local.pfx}-pg-${local.sfx}.private.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgresql" {
  count                 = var.enable_tier1 ? 1 : 0
  name                  = "pg-vnet-link"
  private_dns_zone_name = azurerm_private_dns_zone.postgresql[0].name
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_id    = azurerm_virtual_network.main.id
}

# PostgreSQL - Private (SHOULD NOT DETECT)
resource "azurerm_postgresql_flexible_server" "private" {
  count                         = var.enable_tier1 ? 1 : 0
  name                          = "${local.pfx}-pg-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  administrator_login           = "pgadmin"
  administrator_password        = random_password.db[0].result
  sku_name                      = "B_Standard_B1ms"
  version                       = "16"
  delegated_subnet_id           = azurerm_subnet.postgresql[0].id
  private_dns_zone_id           = azurerm_private_dns_zone.postgresql[0].id
  public_network_access_enabled = false

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgresql]

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "PostgreSQL-Private" })
}

# ============================================================================
# TIER 2: Cognitive Services, Search Service, Function Apps
# ============================================================================

# Cognitive Services - Public (SHOULD DETECT)
resource "azurerm_cognitive_account" "public" {
  count                         = var.enable_tier2 ? 1 : 0
  name                          = "${local.pfx}-cog-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  kind                          = "TextAnalytics"
  sku_name                      = "S"
  custom_subdomain_name         = "${local.pfx}-cog-${local.sfx}"
  public_network_access_enabled = true

  network_acls { default_action = "Allow" }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "CognitiveServices-Public" })
}

# Search Service - Public (SHOULD DETECT)
resource "azurerm_search_service" "public" {
  count                         = var.enable_tier2 ? 1 : 0
  name                          = "${local.pfx}-search-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  sku                           = "free"
  public_network_access_enabled = true

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "SearchService-Public" })
}

# Function App dependencies
resource "azurerm_storage_account" "func" {
  count                    = var.enable_tier2 ? 1 : 0
  name                     = "${local.pfx}func${local.sfx}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = local.loc
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

resource "azurerm_service_plan" "func" {
  count               = var.enable_tier2 ? 1 : 0
  name                = "${local.pfx}-funcplan-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  os_type             = "Linux"
  sku_name            = "Y1"
  tags                = local.tags
}

# Function App - Public (SHOULD DETECT)
resource "azurerm_linux_function_app" "public" {
  count                         = var.enable_tier2 ? 1 : 0
  name                          = "${local.pfx}-func-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  storage_account_name          = azurerm_storage_account.func[0].name
  storage_account_access_key    = azurerm_storage_account.func[0].primary_access_key
  service_plan_id               = azurerm_service_plan.func[0].id
  public_network_access_enabled = true

  site_config {
    application_stack { python_version = "3.11" }
  }

  app_settings = { "FUNCTIONS_WORKER_RUNTIME" = "python" }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "FunctionApp-Public" })
}

# Cognitive Services - Private (SHOULD NOT DETECT by cognitive_services_public_access)
# TN: publicNetworkAccess=disabled and defaultAction=Deny
resource "azurerm_cognitive_account" "private" {
  count                         = var.enable_tier2 ? 1 : 0
  name                          = "${local.pfx}-cog-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  kind                          = "TextAnalytics"
  sku_name                      = "S"
  custom_subdomain_name         = "${local.pfx}-cog-prv-${local.sfx}"
  public_network_access_enabled = false

  network_acls { default_action = "Deny" }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "CognitiveServices-Private" })
}

# Search Service - Private (SHOULD NOT DETECT by search_service_public_access)
# TN: publicNetworkAccess=disabled
# Note: basic SKU required (~$0.10/hr) - free SKU only allows one per subscription
resource "azurerm_search_service" "private" {
  count                         = var.enable_tier2 ? 1 : 0
  name                          = "${local.pfx}-search-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  sku                           = "basic"
  public_network_access_enabled = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "SearchService-Private" })
}

# Function App - Private (SHOULD NOT DETECT by function_apps_public_http_triggers)
# TN: publicNetworkAccess=disabled (shares existing service plan and storage)
resource "azurerm_linux_function_app" "private" {
  count                         = var.enable_tier2 ? 1 : 0
  name                          = "${local.pfx}-func-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  storage_account_name          = azurerm_storage_account.func[0].name
  storage_account_access_key    = azurerm_storage_account.func[0].primary_access_key
  service_plan_id               = azurerm_service_plan.func[0].id
  public_network_access_enabled = false

  site_config {
    application_stack { python_version = "3.11" }
  }

  app_settings = { "FUNCTIONS_WORKER_RUNTIME" = "python" }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "FunctionApp-Private" })
}

# ============================================================================
# TIER 3: IoT Hub, Event Grid Topics, Notification Hubs
# ============================================================================

# IoT Hub - Public (SHOULD DETECT)
resource "azurerm_iothub" "public" {
  count                         = var.enable_tier3 ? 1 : 0
  name                          = "${local.pfx}-iot-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  public_network_access_enabled = true

  sku {
    name     = "B1"
    capacity = 1
  }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "IoTHub-Public" })
}

# Event Grid Topic - Public (SHOULD DETECT)
resource "azurerm_eventgrid_topic" "public" {
  count                         = var.enable_tier3 ? 1 : 0
  name                          = "${local.pfx}-egt-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  public_network_access_enabled = true

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "EventGridTopic-Public" })
}

# Event Grid Topic - Private (SHOULD NOT DETECT)
resource "azurerm_eventgrid_topic" "private" {
  count                         = var.enable_tier3 ? 1 : 0
  name                          = "${local.pfx}-egt-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  public_network_access_enabled = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "EventGridTopic-Private" })
}

# Notification Hub Namespace - Public (SHOULD DETECT)
resource "azurerm_notification_hub_namespace" "public" {
  count               = var.enable_tier3 ? 1 : 0
  name                = "${local.pfx}-nhns-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  namespace_type      = "NotificationHub"
  sku_name            = "Free"

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "NotificationHubs-Public" })
}

# IoT Hub - Private (SHOULD NOT DETECT by iot_hub_public_access)
# TN: publicNetworkAccess=disabled (~$0.03/hr for B1)
resource "azurerm_iothub" "private" {
  count                         = var.enable_tier3 ? 1 : 0
  name                          = "${local.pfx}-iot-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  public_network_access_enabled = false

  sku {
    name     = "B1"
    capacity = 1
  }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "IoTHub-Private" })
}

# NOTE: Notification Hub Namespace does not support disabling public network access
# in azurerm ~> 3.0 provider for Free/Basic SKU. No TN resource can be created.
# The KQL uses coalesce(properties.publicNetworkAccess, 'enabled') which defaults to
# 'enabled' when the property is not set, and Free/Basic SKUs cannot override it.

# ============================================================================
# TIER 4A: App Configuration, Data Explorer, Container Instances, Databricks
# ============================================================================

# App Configuration - Public (SHOULD DETECT)
resource "azurerm_app_configuration" "public" {
  count                 = var.enable_tier4a ? 1 : 0
  name                  = "${local.pfx}-appconf-pub-${local.sfx}"
  resource_group_name   = azurerm_resource_group.main.name
  location              = local.loc
  sku                   = "free"
  public_network_access = "Enabled"

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "AppConfiguration-Public" })
}

# App Configuration - Private (SHOULD NOT DETECT)
resource "azurerm_app_configuration" "private" {
  count                 = var.enable_tier4a ? 1 : 0
  name                  = "${local.pfx}-appconf-prv-${local.sfx}"
  resource_group_name   = azurerm_resource_group.main.name
  location              = local.loc
  sku                   = "standard"
  public_network_access = "Disabled"

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "AppConfiguration-Private" })
}

# Data Explorer (Kusto) - Public (SHOULD DETECT) - Takes ~15 min to provision
resource "azurerm_kusto_cluster" "public" {
  count                         = var.enable_tier4a ? 1 : 0
  name                          = "${local.pfx}kusto${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  public_network_access_enabled = true

  sku {
    name     = "Dev(No SLA)_Standard_E2a_v4"
    capacity = 1
  }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "DataExplorer-Public" })
}

# Container Instance - Public (SHOULD DETECT)
resource "azurerm_container_group" "public" {
  count               = var.enable_tier4a ? 1 : 0
  name                = "${local.pfx}-ci-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
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

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "ContainerInstance-Public" })
}

# Container Instance - Private (SHOULD NOT DETECT)
resource "azurerm_container_group" "private" {
  count               = var.enable_tier4a ? 1 : 0
  name                = "${local.pfx}-ci-prv-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  os_type             = "Linux"
  ip_address_type     = "Private"
  subnet_ids          = [azurerm_subnet.container[0].id]

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

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "ContainerInstance-Private" })
}

# Databricks - Public (SHOULD DETECT)
resource "azurerm_databricks_workspace" "public" {
  count                         = var.enable_tier4a ? 1 : 0
  name                          = "${local.pfx}-dbw-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  sku                           = "trial"
  public_network_access_enabled = true

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "Databricks-Public" })
}

# Data Explorer (Kusto) - Private (SHOULD NOT DETECT by data_explorer_public_access)
# TN: publicNetworkAccess=Disabled (~$0.20/hr Dev SKU, takes ~15 min to provision)
resource "azurerm_kusto_cluster" "private" {
  count                         = var.enable_tier4a ? 1 : 0
  name                          = "${local.pfx}kstprv${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  public_network_access_enabled = false

  sku {
    name     = "Dev(No SLA)_Standard_E2a_v4"
    capacity = 1
  }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "DataExplorer-Private" })
}

# Databricks - Private (SHOULD NOT DETECT by databricks_public_access)
# TN: publicNetworkAccess=disabled (premium SKU required to disable public access)
resource "azurerm_databricks_workspace" "private" {
  count                         = var.enable_tier4a ? 1 : 0
  name                          = "${local.pfx}-dbw-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  sku                           = "premium"
  public_network_access_enabled = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "Databricks-Private" })
}

# ============================================================================
# TIER 4B: Synapse Analytics, ML Workspace
# ============================================================================

# Synapse dependency: Storage + Data Lake Gen2
resource "azurerm_storage_account" "synapse" {
  count                    = var.enable_tier4b ? 1 : 0
  name                     = "${local.pfx}synsa${local.sfx}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = local.loc
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  is_hns_enabled           = true
  tags                     = local.tags
}

resource "azurerm_storage_data_lake_gen2_filesystem" "synapse" {
  count              = var.enable_tier4b ? 1 : 0
  name               = "synapsefs"
  storage_account_id = azurerm_storage_account.synapse[0].id
}

# Synapse Analytics - Public (SHOULD DETECT)
resource "azurerm_synapse_workspace" "public" {
  count                                = var.enable_tier4b ? 1 : 0
  name                                 = "${local.pfx}-syn-pub-${local.sfx}"
  resource_group_name                  = azurerm_resource_group.main.name
  location                             = local.loc
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.synapse[0].id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = "P@ssw0rd1234!"
  public_network_access_enabled        = true

  identity { type = "SystemAssigned" }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "Synapse-Public" })
}

# ML Workspace dependencies
resource "azurerm_storage_account" "ml" {
  count                    = var.enable_tier4b ? 1 : 0
  name                     = "${local.pfx}mlsa${local.sfx}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = local.loc
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

resource "azurerm_key_vault" "ml" {
  count               = var.enable_tier4b ? 1 : 0
  name                = "${local.pfx}-mlkv-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
  tags                = local.tags
}

resource "azurerm_log_analytics_workspace" "ml" {
  count               = var.enable_tier4b ? 1 : 0
  name                = "${local.pfx}-mllaw-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

resource "azurerm_application_insights" "ml" {
  count               = var.enable_tier4b ? 1 : 0
  name                = "${local.pfx}-mlai-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  application_type    = "web"
  workspace_id        = azurerm_log_analytics_workspace.ml[0].id
  tags                = local.tags
}

# ML Workspace - Public (SHOULD DETECT)
resource "azurerm_machine_learning_workspace" "public" {
  count                         = var.enable_tier4b ? 1 : 0
  name                          = "${local.pfx}-mlw-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  application_insights_id       = azurerm_application_insights.ml[0].id
  key_vault_id                  = azurerm_key_vault.ml[0].id
  storage_account_id            = azurerm_storage_account.ml[0].id
  public_network_access_enabled = true

  identity { type = "SystemAssigned" }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "MLWorkspace-Public" })
}

# Synapse DL Gen2 filesystem for private workspace (shares storage account)
resource "azurerm_storage_data_lake_gen2_filesystem" "synapse_private" {
  count              = var.enable_tier4b ? 1 : 0
  name               = "synapseprvfs"
  storage_account_id = azurerm_storage_account.synapse[0].id
}

# Synapse - Private (SHOULD NOT DETECT by synapse_public_access)
# TN: publicNetworkAccess=disabled (shares existing synapse storage account)
resource "azurerm_synapse_workspace" "private" {
  count                                = var.enable_tier4b ? 1 : 0
  name                                 = "${local.pfx}-syn-prv-${local.sfx}"
  resource_group_name                  = azurerm_resource_group.main.name
  location                             = local.loc
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.synapse_private[0].id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = "P@ssw0rd1234!"
  public_network_access_enabled        = false

  identity { type = "SystemAssigned" }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "Synapse-Private" })
}

# ML Workspace - Private (SHOULD NOT DETECT by ml_workspace_public_access)
# TN: publicNetworkAccess=disabled (shares existing ML dependencies)
resource "azurerm_machine_learning_workspace" "private" {
  count                         = var.enable_tier4b ? 1 : 0
  name                          = "${local.pfx}-mlw-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  application_insights_id       = azurerm_application_insights.ml[0].id
  key_vault_id                  = azurerm_key_vault.ml[0].id
  storage_account_id            = azurerm_storage_account.ml[0].id
  public_network_access_enabled = false

  identity { type = "SystemAssigned" }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "MLWorkspace-Private" })
}

# ============================================================================
# TIER 4C: Container Apps, Logic Apps, Application Gateway
# ============================================================================

# Container App Environment dependency
resource "azurerm_log_analytics_workspace" "tier4c" {
  count               = var.enable_tier4c ? 1 : 0
  name                = "${local.pfx}-law-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

resource "azurerm_container_app_environment" "main" {
  count                      = var.enable_tier4c ? 1 : 0
  name                       = "${local.pfx}-cae-${local.sfx}"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = local.loc
  log_analytics_workspace_id = azurerm_log_analytics_workspace.tier4c[0].id
  tags                       = local.tags
}

# Container App - Public (SHOULD DETECT)
resource "azurerm_container_app" "public" {
  count                        = var.enable_tier4c ? 1 : 0
  name                         = "${local.pfx}-ca-pub-${local.sfx}"
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main[0].id
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

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "ContainerApp-Public" })
}

# Container App - Private (SHOULD NOT DETECT by container_apps_public_access)
# TN: ingress external_enabled=false (internal-only, shares existing environment)
resource "azurerm_container_app" "private" {
  count                        = var.enable_tier4c ? 1 : 0
  name                         = "${local.pfx}-ca-prv-${local.sfx}"
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main[0].id
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
    external_enabled = false
    target_port      = 80
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "ContainerApp-Private" })
}

# Logic App - Public (SHOULD DETECT) - No access control = publicly triggerable
resource "azurerm_logic_app_workflow" "public" {
  count               = var.enable_tier4c ? 1 : 0
  name                = "${local.pfx}-la-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "LogicApp-Public" })
}

# Logic App - Private (SHOULD NOT DETECT) - Has IP restrictions
resource "azurerm_logic_app_workflow" "private" {
  count               = var.enable_tier4c ? 1 : 0
  name                = "${local.pfx}-la-prv-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc

  access_control {
    trigger { allowed_caller_ip_address_range = ["10.0.0.0/8"] }
  }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "LogicApp-Private" })
}

# Application Gateway - Public (SHOULD DETECT)
resource "azurerm_public_ip" "appgw" {
  count               = var.enable_tier4c ? 1 : 0
  name                = "${local.pfx}-appgw-pip-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_application_gateway" "public" {
  count               = var.enable_tier4c ? 1 : 0
  name                = "${local.pfx}-appgw-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc

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
    subnet_id = azurerm_subnet.appgw[0].id
  }

  frontend_port {
    name = "http-port"
    port = 80
  }

  frontend_ip_configuration {
    name                 = "public-frontend"
    public_ip_address_id = azurerm_public_ip.appgw[0].id
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

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "ApplicationGateway-Public" })
}

# NOTE: Application Gateway private (internal-only) TN would require a second App Gateway
# (~$0.26/hr) with only private frontend IP configuration. Skipped due to cost.
# The KQL checks for isnotnull(frontendIPConfig.properties.publicIPAddress) - an
# internal-only App GW would have no public IP in frontendIPConfigurations.

# ============================================================================
# TIER 5A: Storage Account, Key Vault, App Service, Data Factory, Log Analytics, Container Registry
# ============================================================================

# Storage Account - Public (SHOULD DETECT)
resource "azurerm_storage_account" "public" {
  count                           = var.enable_tier5a ? 1 : 0
  name                            = "${local.pfx}sapub${local.sfx}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = local.loc
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  public_network_access_enabled   = true
  allow_nested_items_to_be_public = true

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "StorageAccount-Public" })
}

# Storage Account - Private (SHOULD NOT DETECT)
resource "azurerm_storage_account" "private" {
  count                           = var.enable_tier5a ? 1 : 0
  name                            = "${local.pfx}saprv${local.sfx}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = local.loc
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  public_network_access_enabled   = false
  allow_nested_items_to_be_public = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "StorageAccount-Private" })
}

# Key Vault - Public (SHOULD DETECT)
resource "azurerm_key_vault" "public" {
  count                         = var.enable_tier5a ? 1 : 0
  name                          = "${local.pfx}-kv-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  public_network_access_enabled = true

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "KeyVault-Public" })
}

# Key Vault - Private (SHOULD NOT DETECT)
resource "azurerm_key_vault" "private" {
  count                         = var.enable_tier5a ? 1 : 0
  name                          = "${local.pfx}-kv-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  public_network_access_enabled = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "KeyVault-Private" })
}

# App Service dependency
resource "azurerm_service_plan" "appservice" {
  count               = var.enable_tier5a ? 1 : 0
  name                = "${local.pfx}-asp-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  os_type             = "Linux"
  sku_name            = "F1"
  tags                = local.tags
}

# App Service - Public (SHOULD DETECT)
resource "azurerm_linux_web_app" "public" {
  count                         = var.enable_tier5a ? 1 : 0
  name                          = "${local.pfx}-app-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  service_plan_id               = azurerm_service_plan.appservice[0].id
  public_network_access_enabled = true

  site_config { always_on = false }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "AppService-Public" })
}

# App Service - Private (SHOULD NOT DETECT)
resource "azurerm_linux_web_app" "private" {
  count                         = var.enable_tier5a ? 1 : 0
  name                          = "${local.pfx}-app-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  service_plan_id               = azurerm_service_plan.appservice[0].id
  public_network_access_enabled = false

  site_config { always_on = false }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "AppService-Private" })
}

# Data Factory - Public (SHOULD DETECT)
resource "azurerm_data_factory" "public" {
  count                  = var.enable_tier5a ? 1 : 0
  name                   = "${local.pfx}-adf-pub-${local.sfx}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = local.loc
  public_network_enabled = true

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "DataFactory-Public" })
}

# Log Analytics Workspace - Public (SHOULD DETECT)
# Template checks publicNetworkAccessForIngestion/Query == Enabled
resource "azurerm_log_analytics_workspace" "public" {
  count                      = var.enable_tier5a ? 1 : 0
  name                       = "${local.pfx}-law-pub-${local.sfx}"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = local.loc
  sku                        = "PerGB2018"
  retention_in_days          = 30
  internet_ingestion_enabled = true
  internet_query_enabled     = true

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "LogAnalytics-Public" })
}

# Container Registry - Public (SHOULD DETECT)
resource "azurerm_container_registry" "public" {
  count                         = var.enable_tier5a ? 1 : 0
  name                          = "${local.pfx}acrpub${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  sku                           = "Basic"
  public_network_access_enabled = true
  admin_enabled                 = false

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "ContainerRegistry-Public" })
}

# Data Factory - Private (SHOULD NOT DETECT by data_factory_public_access)
# TN: publicNetworkAccess=disabled (~$0)
resource "azurerm_data_factory" "private" {
  count                  = var.enable_tier5a ? 1 : 0
  name                   = "${local.pfx}-adf-prv-${local.sfx}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = local.loc
  public_network_enabled = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "DataFactory-Private" })
}

# Log Analytics Workspace - Private (SHOULD NOT DETECT by log_analytics_public)
# TN: both publicNetworkAccessForIngestion and ForQuery set to Disabled
resource "azurerm_log_analytics_workspace" "private" {
  count                      = var.enable_tier5a ? 1 : 0
  name                       = "${local.pfx}-law-prv-${local.sfx}"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = local.loc
  sku                        = "PerGB2018"
  retention_in_days          = 30
  internet_ingestion_enabled = false
  internet_query_enabled     = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "LogAnalytics-Private" })
}

# Container Registry - Private (SHOULD NOT DETECT by container_registries_public)
# TN: publicNetworkAccess=disabled (requires Premium SKU, ~$0.07/hr)
resource "azurerm_container_registry" "private" {
  count                         = var.enable_tier5a ? 1 : 0
  name                          = "${local.pfx}acrprv${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  sku                           = "Premium"
  public_network_access_enabled = false
  admin_enabled                 = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "ContainerRegistry-Private" })
}

# ============================================================================
# TIER 5B: SQL Server, Cosmos DB, Service Bus, Event Hub, Redis Cache, ACR Anonymous Pull
# ============================================================================

resource "random_password" "sql" {
  count            = var.enable_tier5b ? 1 : 0
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# SQL Server - Public (SHOULD DETECT)
resource "azurerm_mssql_server" "public" {
  count                         = var.enable_tier5b ? 1 : 0
  name                          = "${local.pfx}-sql-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  version                       = "12.0"
  administrator_login           = "sqladmin"
  administrator_login_password  = random_password.sql[0].result
  public_network_access_enabled = true

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "SQLServer-Public" })
}

# SQL Server - Private (SHOULD NOT DETECT)
resource "azurerm_mssql_server" "private" {
  count                         = var.enable_tier5b ? 1 : 0
  name                          = "${local.pfx}-sql-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  version                       = "12.0"
  administrator_login           = "sqladmin"
  administrator_login_password  = random_password.sql[0].result
  public_network_access_enabled = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "SQLServer-Private" })
}

# Cosmos DB - Public (SHOULD DETECT)
resource "azurerm_cosmosdb_account" "public" {
  count                         = var.enable_tier5b ? 1 : 0
  name                          = "${local.pfx}-cosmos-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
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
    location          = local.loc
    failover_priority = 0
  }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "CosmosDB-Public" })
}

# Service Bus - Public (SHOULD DETECT)
resource "azurerm_servicebus_namespace" "public" {
  count               = var.enable_tier5b ? 1 : 0
  name                = "${local.pfx}-sb-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  sku                 = "Basic"

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "ServiceBus-Public" })
}

# Event Hub - Public (SHOULD DETECT)
resource "azurerm_eventhub_namespace" "public" {
  count               = var.enable_tier5b ? 1 : 0
  name                = "${local.pfx}-eh-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  sku                 = "Basic"

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "EventHub-Public" })
}

# Redis Cache - Public (SHOULD DETECT)
# Template checks: no subnet_id (no VNet) AND publicNetworkAccess != disabled
resource "azurerm_redis_cache" "public" {
  count                         = var.enable_tier5b ? 1 : 0
  name                          = "${local.pfx}-redis-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  capacity                      = 0
  family                        = "C"
  sku_name                      = "Basic"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = true

  redis_configuration {}

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "RedisCache-Public" })
}

# Container Registry Standard - Anonymous Pull (SHOULD DETECT by acr_anonymous_pull template)
resource "azurerm_container_registry" "anon_pull" {
  count                         = var.enable_tier5b ? 1 : 0
  name                          = "${local.pfx}acranon${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  sku                           = "Standard"
  public_network_access_enabled = true
  admin_enabled                 = false
  anonymous_pull_enabled        = true

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "ACR-AnonymousPull" })
}

# Cosmos DB - Private (SHOULD NOT DETECT by cosmos_db_public)
# TN: publicNetworkAccess=disabled (serverless, ~$0 idle)
resource "azurerm_cosmosdb_account" "private" {
  count                         = var.enable_tier5b ? 1 : 0
  name                          = "${local.pfx}-cosmos-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  public_network_access_enabled = false

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = local.loc
    failover_priority = 0
  }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "CosmosDB-Private" })
}

# NOTE: Service Bus private TN requires Premium SKU (~$0.67/hr). Skipped due to cost.
# The KQL checks publicNetworkAccess != 'disabled' AND defaultAction == 'allow'.
# Basic/Standard SKUs do not support disabling public network access in azurerm ~> 3.0.

# Event Hub - Private (SHOULD NOT DETECT by event_hub_public)
# TN: publicNetworkAccess=disabled (Standard tier supports this, ~$0.015/hr)
resource "azurerm_eventhub_namespace" "private" {
  count                         = var.enable_tier5b ? 1 : 0
  name                          = "${local.pfx}-eh-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  sku                           = "Standard"
  public_network_access_enabled = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "EventHub-Private" })
}

# Redis Cache - Private (SHOULD NOT DETECT by redis_cache_public)
# TN: publicNetworkAccess=disabled (~$0.017/hr for Basic C0)
resource "azurerm_redis_cache" "private" {
  count                         = var.enable_tier5b ? 1 : 0
  name                          = "${local.pfx}-redis-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  capacity                      = 0
  family                        = "C"
  sku_name                      = "Basic"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false

  redis_configuration {}

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "RedisCache-Private" })
}

# ACR Anonymous Pull Disabled (SHOULD NOT DETECT by acr_anonymous_pull)
# TN: anonymous_pull_enabled=false (explicit TN for anonymous pull template)
resource "azurerm_container_registry" "anon_pull_disabled" {
  count                         = var.enable_tier5b ? 1 : 0
  name                          = "${local.pfx}acrnoap${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  sku                           = "Standard"
  public_network_access_enabled = true
  admin_enabled                 = false
  anonymous_pull_enabled        = false

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "ACR-AnonymousPullDisabled" })
}

# ============================================================================
# TIER 5C: AKS, API Management, Load Balancer, Virtual Machine
# ============================================================================

# VM subnet
resource "azurerm_subnet" "vm" {
  count                = var.enable_tier5c ? 1 : 0
  name                 = "vm-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.5.0/24"]
}

# AKS - Public (SHOULD DETECT)
# Template checks: enablePrivateCluster == false (default for public AKS)
resource "azurerm_kubernetes_cluster" "public" {
  count               = var.enable_tier5c ? 1 : 0
  name                = "${local.pfx}-aks-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  dns_prefix          = "${local.pfx}-aks-${local.sfx}"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_B2s"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "AKS-Public" })
}

# API Management - Public (SHOULD DETECT)
# Template checks: publicNetworkAccess != disabled AND virtualNetworkType != internal
resource "azurerm_api_management" "public" {
  count               = var.enable_tier5c ? 1 : 0
  name                = "${local.pfx}-apim-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  publisher_name      = "Nebula Testing"
  publisher_email     = "nebula-test@example.com"
  sku_name            = "Consumption_0"

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "APIManagement-Public" })
}

# Load Balancer - Public (SHOULD DETECT)
# Template checks: LB has public IP in frontend configuration
resource "azurerm_public_ip" "lb" {
  count               = var.enable_tier5c ? 1 : 0
  name                = "${local.pfx}-lb-pip-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_lb" "public" {
  count               = var.enable_tier5c ? 1 : 0
  name                = "${local.pfx}-lb-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  sku                 = "Standard"

  frontend_ip_configuration {
    name                 = "public-frontend"
    public_ip_address_id = azurerm_public_ip.lb[0].id
  }

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "LoadBalancer-Public" })
}

# Virtual Machine - Public (SHOULD DETECT)
# Template checks: VM -> NIC -> Public IP -> NSG with inbound allow from Internet

resource "random_password" "vm" {
  count            = var.enable_tier5c ? 1 : 0
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "azurerm_network_security_group" "vm_public" {
  count               = var.enable_tier5c ? 1 : 0
  name                = "${local.pfx}-nsg-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc

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
  count               = var.enable_tier5c ? 1 : 0
  name                = "${local.pfx}-vm-pip-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "vm_public" {
  count               = var.enable_tier5c ? 1 : 0
  name                = "${local.pfx}-nic-pub-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vm[0].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm[0].id
  }

  tags = local.tags
}

resource "azurerm_network_interface_security_group_association" "vm_public" {
  count                     = var.enable_tier5c ? 1 : 0
  network_interface_id      = azurerm_network_interface.vm_public[0].id
  network_security_group_id = azurerm_network_security_group.vm_public[0].id
}

resource "azurerm_linux_virtual_machine" "public" {
  count                           = var.enable_tier5c ? 1 : 0
  name                            = "${local.pfx}-vm-pub-${local.sfx}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = local.loc
  size                            = "Standard_B1ls"
  admin_username                  = "azureuser"
  admin_password                  = random_password.vm[0].result
  disable_password_authentication = false
  network_interface_ids           = [azurerm_network_interface.vm_public[0].id]

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

  tags = merge(local.tags, { ExpectedFind = "true", ResourceType = "VirtualMachine-Public" })
}

# AKS - Private (SHOULD NOT DETECT by aks_public_access)
# TN: enablePrivateCluster=true (~$0.04/hr for B2s node)
resource "azurerm_kubernetes_cluster" "private" {
  count                   = var.enable_tier5c ? 1 : 0
  name                    = "${local.pfx}-aks-prv-${local.sfx}"
  resource_group_name     = azurerm_resource_group.main.name
  location                = local.loc
  dns_prefix              = "${local.pfx}-aksprv-${local.sfx}"
  private_cluster_enabled = true

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_B2s"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "AKS-Private" })
}

# NOTE: API Management private (internal VNet) TN requires Premium SKU (~$5/hr). Skipped due to cost.
# The KQL checks publicNetworkAccess != 'disabled' AND virtualNetworkType != 'internal'.

# Load Balancer - Internal (SHOULD NOT DETECT by load_balancers_public)
# TN: no public IP in frontend (internal-only, ~$0.025/hr)
resource "azurerm_lb" "private" {
  count               = var.enable_tier5c ? 1 : 0
  name                = "${local.pfx}-lb-prv-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  sku                 = "Standard"

  frontend_ip_configuration {
    name                          = "internal-frontend"
    subnet_id                     = azurerm_subnet.vm[0].id
    private_ip_address_allocation = "Dynamic"
  }

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "LoadBalancer-Internal" })
}

# Virtual Machine - Private (SHOULD NOT DETECT by virtual_machines_public)
# TN: no public IP attached to NIC (~$0.008/hr for B1ls)
resource "azurerm_network_interface" "vm_private" {
  count               = var.enable_tier5c ? 1 : 0
  name                = "${local.pfx}-nic-prv-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vm[0].id
    private_ip_address_allocation = "Dynamic"
  }

  tags = local.tags
}

resource "azurerm_linux_virtual_machine" "private" {
  count                           = var.enable_tier5c ? 1 : 0
  name                            = "${local.pfx}-vm-prv-${local.sfx}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = local.loc
  size                            = "Standard_B1ls"
  admin_username                  = "azureuser"
  admin_password                  = random_password.vm[0].result
  disable_password_authentication = false
  network_interface_ids           = [azurerm_network_interface.vm_private[0].id]

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

  tags = merge(local.tags, { ExpectedFind = "false", ResourceType = "VirtualMachine-Private" })
}
