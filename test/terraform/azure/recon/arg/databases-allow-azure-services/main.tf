# Nebula Azure Databases Allow Azure Services - Testing Infrastructure
# Template: databases_allow_azure_services
# Purpose: Deploy database resources with/without "Allow Azure Services" firewall rules
#          to validate enricher-based detection of the 0.0.0.0-0.0.0.0 bypass.
#
# KQL Logic (ARG query just lists databases, enricher checks firewall rules):
#   type in~ ('Microsoft.Sql/servers', 'Microsoft.Synapse/workspaces',
#             'Microsoft.DBforPostgreSQL/flexibleServers',
#             'Microsoft.DBforMySQL/flexibleServers')
#   Enricher checks for AllowAllWindowsAzureIps / AllowAllAzureIps rules
#
# Cost estimate: ~$0.85/hr
#   - SQL Server: Free (pay-per-use, no DB created)
#   - PostgreSQL Flex B1ms: ~$0.40/hr
#   - MySQL Flex B1s: ~$0.40/hr
#   - Synapse serverless: ~$0.05/hr

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
  pfx = "nbdb" # nebula-databases
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-databases-allow-azure-services-testing"
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
# TRUE POSITIVE 1: SQL Server with AllowAllWindowsAzureIps firewall rule
# SHOULD DETECT - has 0.0.0.0-0.0.0.0 firewall rule
# ============================================================================

resource "azurerm_mssql_server" "allow_azure" {
  name                         = "${local.pfx}-sql-azure-${local.sfx}"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = local.loc
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = random_password.db.result

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "SQLServer-AllowAzureServices"
  })
}

resource "azurerm_mssql_firewall_rule" "allow_azure_services" {
  name             = "AllowAllWindowsAzureIps"
  server_id        = azurerm_mssql_server.allow_azure.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# ============================================================================
# TRUE NEGATIVE 1: SQL Server without AllowAzureServices rule
# SHOULD NOT DETECT - no 0.0.0.0 firewall rule
# ============================================================================

resource "azurerm_mssql_server" "no_azure" {
  name                         = "${local.pfx}-sql-noaz-${local.sfx}"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = local.loc
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = random_password.db.result

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "SQLServer-NoAzureServices"
  })
}

# ============================================================================
# TRUE POSITIVE 2: PostgreSQL Flexible Server with AllowAllAzureIps
# SHOULD DETECT - has allow azure IPs firewall rule + public access
# ============================================================================

resource "azurerm_postgresql_flexible_server" "allow_azure" {
  count                  = var.enable_postgresql ? 1 : 0
  name                   = "${local.pfx}-pg-azure-${local.sfx}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = local.loc
  administrator_login    = "pgadmin"
  administrator_password = random_password.db.result
  sku_name               = "B_Standard_B1ms"
  version                = "16"

  lifecycle { ignore_changes = [zone] }

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "PostgreSQL-AllowAzureServices"
  })
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_azure" {
  count            = var.enable_postgresql ? 1 : 0
  name             = "AllowAllAzureIps"
  server_id        = azurerm_postgresql_flexible_server.allow_azure[0].id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# ============================================================================
# TRUE POSITIVE 3: MySQL Flexible Server with AllowAllAzureIps
# SHOULD DETECT - has allow azure IPs firewall rule + public access
# ============================================================================

resource "azurerm_mysql_flexible_server" "allow_azure" {
  count                  = var.enable_mysql ? 1 : 0
  name                   = "${local.pfx}-mysql-azure-${local.sfx}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = local.loc
  administrator_login    = "mysqladmin"
  administrator_password = random_password.db.result
  sku_name               = "B_Standard_B1s"

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "MySQL-AllowAzureServices"
  })
}

resource "azurerm_mysql_flexible_server_firewall_rule" "allow_azure" {
  count               = var.enable_mysql ? 1 : 0
  name                = "AllowAllAzureIps"
  resource_group_name = azurerm_resource_group.main.name
  server_name         = azurerm_mysql_flexible_server.allow_azure[0].name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "0.0.0.0"
}

# ============================================================================
# TRUE NEGATIVE 2: PostgreSQL Flexible Server without AllowAzureServices
# SHOULD NOT DETECT - no azure services firewall rule
# ============================================================================

resource "azurerm_postgresql_flexible_server" "no_azure" {
  count                  = var.enable_postgresql ? 1 : 0
  name                   = "${local.pfx}-pg-noaz-${local.sfx}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = local.loc
  administrator_login    = "pgadmin"
  administrator_password = random_password.db.result
  sku_name               = "B_Standard_B1ms"
  version                = "16"

  lifecycle { ignore_changes = [zone] }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "PostgreSQL-NoAzureServices"
  })
}

# ============================================================================
# TRUE NEGATIVE 3: MySQL Flexible Server without AllowAzureServices
# SHOULD NOT DETECT - no azure services firewall rule
# ============================================================================

resource "azurerm_mysql_flexible_server" "no_azure" {
  count                  = var.enable_mysql ? 1 : 0
  name                   = "${local.pfx}-mysql-noaz-${local.sfx}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = local.loc
  administrator_login    = "mysqladmin"
  administrator_password = random_password.db.result
  sku_name               = "B_Standard_B1s"

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "MySQL-NoAzureServices"
  })
}

# ============================================================================
# TRUE POSITIVE 4: Synapse Workspace with AllowAllWindowsAzureIps
# SHOULD DETECT - has 0.0.0.0-0.0.0.0 firewall rule
# ============================================================================

resource "azurerm_storage_account" "synapse" {
  count                    = var.enable_synapse ? 1 : 0
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
  count              = var.enable_synapse ? 1 : 0
  name               = "synapsefs"
  storage_account_id = azurerm_storage_account.synapse[0].id
}

resource "azurerm_synapse_workspace" "allow_azure" {
  count                                = var.enable_synapse ? 1 : 0
  name                                 = "${local.pfx}-syn-azure-${local.sfx}"
  resource_group_name                  = azurerm_resource_group.main.name
  location                             = local.loc
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.synapse[0].id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = random_password.db.result

  identity { type = "SystemAssigned" }

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "Synapse-AllowAzureServices"
  })
}

resource "azurerm_synapse_firewall_rule" "allow_azure_services" {
  count                = var.enable_synapse ? 1 : 0
  name                 = "AllowAllWindowsAzureIps"
  synapse_workspace_id = azurerm_synapse_workspace.allow_azure[0].id
  start_ip_address     = "0.0.0.0"
  end_ip_address       = "0.0.0.0"
}

# ============================================================================
# TRUE NEGATIVE 4: Synapse Workspace without AllowAzureServices
# SHOULD NOT DETECT - no azure services firewall rule
# ============================================================================

resource "azurerm_storage_account" "synapse_noaz" {
  count                    = var.enable_synapse ? 1 : 0
  name                     = "${local.pfx}synna${local.sfx}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = local.loc
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  is_hns_enabled           = true
  tags                     = local.tags
}

resource "azurerm_storage_data_lake_gen2_filesystem" "synapse_noaz" {
  count              = var.enable_synapse ? 1 : 0
  name               = "synapsefs"
  storage_account_id = azurerm_storage_account.synapse_noaz[0].id
}

resource "azurerm_synapse_workspace" "no_azure" {
  count                                = var.enable_synapse ? 1 : 0
  name                                 = "${local.pfx}-syn-noaz-${local.sfx}"
  resource_group_name                  = azurerm_resource_group.main.name
  location                             = local.loc
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.synapse_noaz[0].id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = random_password.db.result

  identity { type = "SystemAssigned" }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "Synapse-NoAzureServices"
  })
}
