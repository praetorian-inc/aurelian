# Nebula Azure Cloud Shell Storage Detection - Testing Infrastructure
# Template: cloud_shell_storage_detection (storage_accounts_cloud_shell)
# Purpose: Deploy storage accounts matching Cloud Shell naming patterns to validate detection
#
# KQL Logic:
#   type =~ 'Microsoft.Storage/storageAccounts'
#   where name startswith 'cs' and name matches regex '^cs[a-f0-9]{18}$'
#     OR tags['ms-resource-usage'] =~ 'azure-cloud-shell'
#
# TP1: Storage account with Cloud Shell naming pattern (cs + 18 hex chars)
# TP2: Storage account with ms-resource-usage=azure-cloud-shell tag
# TN: Regular storage account (no Cloud Shell indicators)
#
# Cost estimate: ~$0.01/hr (storage accounts have minimal cost when empty)

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

resource "random_string" "hex18" {
  length  = 18
  special = false
  upper   = false
  # Only hex characters: 0-9, a-f
  # random_string with numeric=true, lower=true covers a-z + 0-9
  # We'll use a regex-valid hex name below
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  pfx = "nbcs" # nebula-cloud-shell
  sfx = random_string.suffix.result
  # Generate a valid Cloud Shell storage name: cs + 18 hex chars
  # Use md5 hash truncated to 18 chars to guarantee hex-only characters
  cs_hex = substr(md5(random_string.suffix.result), 0, 18)
}

resource "azurerm_resource_group" "main" {
  name     = "${local.pfx}-rg-${local.sfx}"
  location = var.location
  tags = {
    purpose   = "nebula-testing"
    template  = "cloud_shell_storage_detection"
    temporary = "true"
  }
}

# ═══════════════════════════════════════════════════════════════
# TRUE POSITIVE 1: Storage account matching Cloud Shell naming pattern
# Name: cs + 18 hex chars (matches regex '^cs[a-f0-9]{18}$')
# Should be DETECTED by cloud_shell_storage_detection
# ═══════════════════════════════════════════════════════════════
resource "azurerm_storage_account" "cs_name_pattern" {
  count = var.enable_tp_name ? 1 : 0

  name                     = "cs${local.cs_hex}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    test_case = "TP-name-pattern"
    expected  = "detected"
  }
}

# ═══════════════════════════════════════════════════════════════
# TRUE POSITIVE 2: Storage account with Cloud Shell tag
# Has ms-resource-usage=azure-cloud-shell tag
# Should be DETECTED by cloud_shell_storage_detection
# ═══════════════════════════════════════════════════════════════
resource "azurerm_storage_account" "cs_tagged" {
  count = var.enable_tp_tag ? 1 : 0

  name                     = "${local.pfx}tag${local.sfx}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    "ms-resource-usage" = "azure-cloud-shell"
    test_case           = "TP-tag"
    expected            = "detected"
  }
}

# ═══════════════════════════════════════════════════════════════
# TRUE NEGATIVE: Regular storage account (no Cloud Shell indicators)
# Should NOT be detected
# ═══════════════════════════════════════════════════════════════
resource "azurerm_storage_account" "regular" {
  count = var.enable_tn ? 1 : 0

  name                     = "${local.pfx}reg${local.sfx}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    test_case = "TN"
    expected  = "not_detected"
  }
}
