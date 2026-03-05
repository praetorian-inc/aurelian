// Module: azure-recon-public-resources
// Provisions publicly-accessible Azure resources for integration testing of
// the AzurePublicResourcesModule. Each resource is configured to match at
// least one embedded ARG query template.
//
// ==================== TEST CASES ====================
//
// | #  | Resource Name                  | Template Matched                      | Expected Result |
// |----|--------------------------------|---------------------------------------|-----------------|
// | 1  | ${prefix_san}sa                | storage_accounts_public_access        | DETECTED        |
// | 2  | ${prefix}-sql                  | sql_servers_public_access             | DETECTED        |

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
  prefix     = "aurelian-pub-${random_string.suffix.result}"
  prefix_san = "aurelianpub${random_string.suffix.result}"
  location   = var.location
  tags = {
    ManagedBy = "terraform"
    Purpose   = "aurelian-public-resources-testing"
  }
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
# RESOURCE 1: Storage Account with public access (matches storage_accounts_public_access)
# - publicNetworkAccess = Enabled
# - networkAcls.defaultAction = Allow
# - allowBlobPublicAccess = true
#==============================================================================
resource "azurerm_storage_account" "public" {
  name                      = "${local.prefix_san}sa"
  resource_group_name       = azurerm_resource_group.test.name
  location                  = azurerm_resource_group.test.location
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  allow_nested_items_to_be_public = true
  public_network_access_enabled   = true

  network_rules {
    default_action = "Allow"
  }

  tags = local.tags
}

#==============================================================================
# RESOURCE 2: SQL Server with public access (matches sql_servers_public_access)
# - publicNetworkAccess = Enabled (default)
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
