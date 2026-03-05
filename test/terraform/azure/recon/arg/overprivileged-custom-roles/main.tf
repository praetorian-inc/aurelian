# Nebula Azure Overprivileged Custom Roles - Testing Infrastructure
# Template: overprivileged_custom_roles
# Purpose: Deploy custom RBAC roles with/without dangerous permissions to validate detection
#
# KQL Logic:
#   AuthorizationResources
#   | where type =~ 'microsoft.authorization/roledefinitions'
#   | where properties.type == 'CustomRole'
#   | mv-expand permission = properties.permissions
#   | mv-expand action = permission.actions
#   | where action =~ 'Microsoft.Authorization/*' or action =~ '*/write' or action =~ '*' ...
#
# TP: Custom role with Microsoft.Authorization/roleAssignments/write - DETECTED
# TN: Custom role with read-only permissions - NOT detected
#
# Cost estimate: $0.00 (role definitions have no cost)

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
data "azurerm_subscription" "current" {}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  pfx = "nbcr" # nebula-custom-roles
  sfx = random_string.suffix.result
}

resource "azurerm_resource_group" "main" {
  name     = "${local.pfx}-rg-${local.sfx}"
  location = var.location
  tags = {
    purpose   = "nebula-testing"
    template  = "overprivileged_custom_roles"
    temporary = "true"
  }
}

# ═══════════════════════════════════════════════════════════════
# TRUE POSITIVE: Custom role with dangerous Authorization permissions
# Should be DETECTED by overprivileged_custom_roles
# ═══════════════════════════════════════════════════════════════
resource "azurerm_role_definition" "overprivileged" {
  count = var.enable_tp ? 1 : 0

  name        = "${local.pfx}-dangerous-role-${local.sfx}"
  scope       = azurerm_resource_group.main.id
  description = "Nebula test: Custom role with role assignment write permissions (TP)"

  permissions {
    actions = [
      "Microsoft.Authorization/roleAssignments/write",
      "Microsoft.Authorization/roleAssignments/delete",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
    ]
    not_actions = []
  }

  assignable_scopes = [
    azurerm_resource_group.main.id,
  ]
}

# ═══════════════════════════════════════════════════════════════
# TRUE NEGATIVE: Custom role with safe read-only permissions
# Should NOT be detected
# ═══════════════════════════════════════════════════════════════
resource "azurerm_role_definition" "safe" {
  count = var.enable_tn ? 1 : 0

  name        = "${local.pfx}-safe-role-${local.sfx}"
  scope       = azurerm_resource_group.main.id
  description = "Nebula test: Custom role with read-only permissions (TN)"

  permissions {
    actions = [
      "Microsoft.Resources/subscriptions/resourceGroups/read",
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Network/virtualNetworks/read",
    ]
    not_actions = []
  }

  assignable_scopes = [
    azurerm_resource_group.main.id,
  ]
}
