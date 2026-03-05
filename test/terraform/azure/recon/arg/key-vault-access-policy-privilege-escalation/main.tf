# Nebula Azure Key Vault Access Policy Privilege Escalation - Testing Infrastructure
# Template: key_vault_access_policy_privilege_escalation
# Purpose: Deploy Key Vaults with/without RBAC authorization to validate detection
#
# KQL Logic:
#   type =~ 'Microsoft.KeyVault/vaults'
#   enableRbacAuthorization = coalesce(properties.enableRbacAuthorization, false)
#   where enableRbacAuthorization == false
#
# TP: Key Vault using access policies (enableRbacAuthorization=false) - DETECTED
# TN: Key Vault using RBAC authorization (enableRbacAuthorization=true) - NOT detected
#
# Cost estimate: ~$0.00/hr (Key Vaults have no hourly charge, only per-operation)

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
    key_vault {
      purge_soft_delete_on_destroy = false
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
  pfx = "nbkv" # nebula-keyvault
  sfx = random_string.suffix.result
}

resource "azurerm_resource_group" "main" {
  name     = "${local.pfx}-rg-${local.sfx}"
  location = var.location
  tags = {
    purpose   = "nebula-testing"
    template  = "key_vault_access_policy_privilege_escalation"
    temporary = "true"
  }
}

# ═══════════════════════════════════════════════════════════════
# TRUE POSITIVE: Key Vault with access policies (no RBAC)
# Should be DETECTED by key_vault_access_policy_privilege_escalation
# ═══════════════════════════════════════════════════════════════
resource "azurerm_key_vault" "access_policy" {
  count = var.enable_tp ? 1 : 0

  name                       = "${local.pfx}-ap-${local.sfx}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = false
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  # Access policy model - vulnerable to Contributor privilege escalation
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = ["Get", "List", "Set", "Delete"]
    key_permissions    = ["Get", "List"]
  }

  tags = {
    test_case = "TP"
    expected  = "detected"
  }
}

# ═══════════════════════════════════════════════════════════════
# TRUE NEGATIVE: Key Vault with RBAC authorization
# Should NOT be detected
# ═══════════════════════════════════════════════════════════════
resource "azurerm_key_vault" "rbac" {
  count = var.enable_tn ? 1 : 0

  name                       = "${local.pfx}-rb-${local.sfx}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  tags = {
    test_case = "TN"
    expected  = "not_detected"
  }
}
