// Module: azure-recon-public-resources
// Provisions Azure resources with public access configurations so they are
// detected by the public-resources module's ARG query templates.
//
// ==================== TEST CASES ====================
//
// | #  | Resource Name             | Template ID                        | Expected |
// |----|---------------------------|------------------------------------|----------|
// | 1  | ${prefix_san}sa           | storage_accounts_public_access     | DETECTED |
// | 2  | ${prefix}-sql             | sql_servers_public_access          | DETECTED |
// | 3  | ${prefix}-kv              | key_vault_public_access            | DETECTED |
// | 4  | ${prefix}-webapp          | app_services_public_access         | DETECTED |
// | 5  | ${prefix_san}acr          | container_registries_public_access | DETECTED |
// | 6  | ${prefix}-adf             | data_factory_public_access         | DETECTED |

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
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
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
# 1: Storage Account (public blob access, default Allow)
#==============================================================================
resource "azurerm_storage_account" "test" {
  name                            = "${local.prefix_san}sa"
  resource_group_name             = azurerm_resource_group.test.name
  location                        = azurerm_resource_group.test.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  public_network_access_enabled   = true
  tags                            = local.tags
}

#==============================================================================
# 2: SQL Server (public network access enabled)
#==============================================================================
resource "azurerm_mssql_server" "test" {
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
# 3: Key Vault (public access, default allow)
#==============================================================================
resource "azurerm_key_vault" "test" {
  name                       = "${local.prefix}-kv"
  resource_group_name        = azurerm_resource_group.test.name
  location                   = azurerm_resource_group.test.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  public_network_access_enabled = true

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }

  tags = local.tags
}

#==============================================================================
# 4: App Service (public network access)
#==============================================================================
resource "azurerm_service_plan" "test" {
  name                = "${local.prefix}-asp"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  os_type             = "Linux"
  sku_name            = "B1"
  tags                = local.tags
}

resource "azurerm_linux_web_app" "test" {
  name                = "${local.prefix}-webapp"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  service_plan_id     = azurerm_service_plan.test.id

  public_network_access_enabled = true
  site_config {}
  tags = local.tags
}

#==============================================================================
# 5: Container Registry (public access, Basic SKU)
#==============================================================================
resource "azurerm_container_registry" "test" {
  name                          = "${local.prefix_san}acr"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = azurerm_resource_group.test.location
  sku                           = "Basic"
  admin_enabled                 = false
  public_network_access_enabled = true
  tags                          = local.tags
}

#==============================================================================
# 6: Data Factory (public access)
#==============================================================================
resource "azurerm_data_factory" "test" {
  name                            = "${local.prefix}-adf"
  resource_group_name             = azurerm_resource_group.test.name
  location                        = azurerm_resource_group.test.location
  public_network_enabled          = true
  tags                            = local.tags
}

#==============================================================================
# Outputs
#==============================================================================
output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "resource_group_name" {
  value = azurerm_resource_group.test.name
}

output "storage_account_id" {
  value = azurerm_storage_account.test.id
}

output "storage_account_name" {
  value = azurerm_storage_account.test.name
}

output "sql_server_id" {
  value = azurerm_mssql_server.test.id
}

output "sql_server_name" {
  value = azurerm_mssql_server.test.name
}

output "key_vault_id" {
  value = azurerm_key_vault.test.id
}

output "key_vault_name" {
  value = azurerm_key_vault.test.name
}

output "web_app_id" {
  value = azurerm_linux_web_app.test.id
}

output "web_app_name" {
  value = azurerm_linux_web_app.test.name
}

output "container_registry_id" {
  value = azurerm_container_registry.test.id
}

output "container_registry_name" {
  value = azurerm_container_registry.test.name
}

output "data_factory_id" {
  value = azurerm_data_factory.test.id
}

output "data_factory_name" {
  value = azurerm_data_factory.test.name
}
