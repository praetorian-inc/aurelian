// Module: azure-recon-public-resources
// Provisions intentionally public Azure resources for testing the
// azure/recon/public-resources module, which uses ARG query templates
// to detect publicly accessible resources.
//
// ==================== TEST CASES ====================
//
// Each resource is configured with public network access enabled so the
// module's ARG queries will match them.
//
// | #  | Resource                     | Template ID                          | Expected |
// |----|------------------------------|--------------------------------------|----------|
// | 1  | ${prefix_san}sa              | storage_accounts_public_access       | DETECTED |
// | 2  | ${prefix}-kv                 | key_vault_public_access              | DETECTED |
// | 3  | ${prefix}-sql                | sql_servers_public_access            | DETECTED |
// | 4  | ${prefix_san}acr             | container_registries_public_access   | DETECTED |

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

#==============================================================================
# Resource Group
#==============================================================================
resource "azurerm_resource_group" "test" {
  name     = "${local.prefix}-rg"
  location = local.location
  tags     = local.tags
}

#==============================================================================
# RESOURCE 1: Storage Account — publicly accessible
# publicNetworkAccess=Enabled, defaultAction=Allow, allowBlobPublicAccess=true
#==============================================================================
resource "azurerm_storage_account" "public" {
  name                          = "${local.prefix_san}sa"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = azurerm_resource_group.test.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  public_network_access_enabled = true
  allow_nested_items_to_be_public = true

  network_rules {
    default_action = "Allow"
  }

  tags = local.tags
}

#==============================================================================
# RESOURCE 2: Key Vault — publicly accessible
# publicNetworkAccess=Enabled, defaultAction=Allow
#==============================================================================
resource "azurerm_key_vault" "public" {
  name                          = "${local.prefix}-kv"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = azurerm_resource_group.test.location
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

#==============================================================================
# RESOURCE 3: SQL Server — publicly accessible
# publicNetworkAccess=Enabled (default)
#==============================================================================
resource "azurerm_mssql_server" "public" {
  name                         = "${local.prefix}-sql"
  resource_group_name          = azurerm_resource_group.test.name
  location                     = azurerm_resource_group.test.location
  version                      = "12.0"
  administrator_login          = "aurelianadmin"
  administrator_login_password = "P@ssw0rd${random_string.suffix.result}!"
  public_network_access_enabled = true
  tags                         = local.tags
}

#==============================================================================
# RESOURCE 4: Container Registry — publicly accessible (admin enabled)
#==============================================================================
resource "azurerm_container_registry" "public" {
  name                          = "${local.prefix_san}acr"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = azurerm_resource_group.test.location
  sku                           = "Basic"
  admin_enabled                 = true
  public_network_access_enabled = true
  tags                          = local.tags
}
