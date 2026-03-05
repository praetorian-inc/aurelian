# Nebula Azure Kusto Wildcard Trusted Tenants - Testing Infrastructure
# Template: kusto_wildcard_trusted_tenants
# Purpose: Deploy Kusto (Data Explorer) clusters with/without wildcard trusted tenants
#
# KQL Logic:
#   type =~ 'Microsoft.Kusto/clusters'
#   trustedExternalTenants has '*'
#   (wildcard = any Azure AD tenant can authenticate)
#
# Cost estimate: ~$0.25/hr per cluster
#   - Dev(No SLA)_Standard_E2a_v4: ~$0.25/hr
#   - NOTE: Kusto clusters take ~15 min to provision!

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
  pfx = "nbkt" # nebula-kusto-tenants
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-kusto-wildcard-tenants-testing"
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
# TRUE POSITIVE: Kusto cluster with wildcard trusted external tenants
# SHOULD DETECT - trustedExternalTenants contains "*"
# This is the Azure default configuration!
# Takes ~15 min to provision.
# ============================================================================

resource "azurerm_kusto_cluster" "wildcard" {
  count               = var.enable_kusto ? 1 : 0
  name                = "${local.pfx}wild${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc

  sku {
    name     = "Dev(No SLA)_Standard_E2a_v4"
    capacity = 1
  }

  # Default: trustedExternalTenants = [{ value: "*" }]
  # Terraform azurerm doesn't have a direct field for this,
  # but the default Azure behavior is wildcard trust.

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "Kusto-WildcardTrustedTenants"
  })
}

# ============================================================================
# TRUE NEGATIVE: Kusto cluster with restricted trusted tenants
# SHOULD NOT DETECT - trustedExternalTenants restricted to own tenant
# NOTE: Terraform azurerm provider has limited support for trustedExternalTenants.
#       Use az CLI to restrict after creation:
#       az kusto cluster update -g <rg> -n <name> \
#         --trusted-external-tenants value=<your-tenant-id>
# ============================================================================

# The TN must be configured post-deployment via az CLI:
#   TENANT_ID=$(az account show --query tenantId -o tsv)
#   az kusto cluster update \
#     --resource-group <rg> \
#     --name <cluster-name> \
#     --trusted-external-tenants value=$TENANT_ID
#
# Or to disallow all external tenants:
#   az kusto cluster update \
#     --resource-group <rg> \
#     --name <cluster-name> \
#     --trusted-external-tenants '[]'

resource "azurerm_kusto_cluster" "restricted" {
  count               = var.enable_kusto_tn ? 1 : 0
  name                = "${local.pfx}rstr${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc

  sku {
    name     = "Dev(No SLA)_Standard_E2a_v4"
    capacity = 1
  }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "Kusto-RestrictedTenants-PostConfig"
  })
}

# Post-provision step to restrict trusted tenants
resource "null_resource" "restrict_tenants" {
  count = var.enable_kusto_tn ? 1 : 0

  provisioner "local-exec" {
    command = <<-EOT
      az kusto cluster update \
        --resource-group ${azurerm_resource_group.main.name} \
        --name ${azurerm_kusto_cluster.restricted[0].name} \
        --trusted-external-tenants '[]'
    EOT
  }

  depends_on = [azurerm_kusto_cluster.restricted]
}
