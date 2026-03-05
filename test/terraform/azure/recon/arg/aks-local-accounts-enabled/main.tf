# Nebula Azure AKS Local Accounts Enabled - Testing Infrastructure
# Template: aks_local_accounts_enabled
# Purpose: Deploy AKS clusters with/without local accounts to validate detection
#
# KQL Logic:
#   type =~ 'Microsoft.ContainerService/managedClusters'
#   disableLocalAccounts = coalesce(properties.disableLocalAccounts, false)
#   where disableLocalAccounts == false
#
# Cost estimate: ~$0.08/hr per cluster
#   - AKS free control plane + 1x Standard_B2s node: ~$0.08/hr

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

locals {
  pfx = "nbla" # nebula-local-accounts
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-aks-local-accounts-testing"
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
# TRUE POSITIVE: AKS with local accounts enabled (default)
# SHOULD DETECT - disableLocalAccounts=false (default)
# ============================================================================

resource "azurerm_kubernetes_cluster" "local_enabled" {
  count               = var.enable_aks ? 1 : 0
  name                = "${local.pfx}-aks-loc-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  dns_prefix          = "${local.pfx}-loc-${local.sfx}"

  # local_account_disabled defaults to false = local accounts enabled
  local_account_disabled = false

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_B2s"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "AKS-LocalAccountsEnabled"
  })
}

# ============================================================================
# TRUE NEGATIVE: AKS with local accounts disabled (AAD-only)
# SHOULD NOT DETECT - disableLocalAccounts=true
# Requires AAD integration to disable local accounts
# ============================================================================

resource "azurerm_kubernetes_cluster" "local_disabled" {
  count               = var.enable_aks ? 1 : 0
  name                = "${local.pfx}-aks-aad-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  dns_prefix          = "${local.pfx}-aad-${local.sfx}"

  local_account_disabled = true

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_B2s"
  }

  identity {
    type = "SystemAssigned"
  }

  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
    admin_group_object_ids = [data.azurerm_client_config.current.object_id]
  }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "AKS-LocalAccountsDisabled-AADOnly"
  })
}
