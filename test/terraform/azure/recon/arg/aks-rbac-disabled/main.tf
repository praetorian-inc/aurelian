# Nebula Azure AKS RBAC Disabled - Testing Infrastructure
# Template: aks_rbac_disabled
# Purpose: Deploy AKS clusters with/without RBAC to validate detection
#
# KQL Logic:
#   type =~ 'Microsoft.ContainerService/managedClusters'
#   enableRbac = coalesce(properties.enableRBAC, true)
#   where enableRbac == false
#
# IMPORTANT: enableRBAC cannot be changed after cluster creation.
# To create a cluster without RBAC, you must use az CLI:
#   az aks create --enable-rbac=false ...
# The azurerm TF provider always creates clusters with RBAC enabled.
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
  pfx = "nbrb" # nebula-rbac
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-aks-rbac-disabled-testing"
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
# TRUE POSITIVE: AKS with RBAC disabled
# SHOULD DETECT - enableRBAC=false
# NOTE: Terraform azurerm provider does not support creating AKS without RBAC.
#       Use az CLI for the TP cluster:
#       az aks create -g <rg> -n <name> --enable-rbac false --node-count 1 \
#         --node-vm-size Standard_B2s --generate-ssh-keys
# This is created via null_resource provisioner below.
# ============================================================================

resource "null_resource" "aks_no_rbac" {
  count = var.enable_aks_no_rbac ? 1 : 0

  provisioner "local-exec" {
    command = <<-EOT
      az aks create \
        --resource-group ${azurerm_resource_group.main.name} \
        --name ${local.pfx}-aks-norbac-${local.sfx} \
        --disable-rbac \
        --node-count 1 \
        --node-vm-size Standard_B2s \
        --generate-ssh-keys \
        --tags Purpose=nebula-aks-rbac-disabled-testing Environment=test ManagedBy=terraform ExpectedFind=true ResourceType=AKS-RBACDisabled \
        --no-wait
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = "az aks delete --resource-group ${self.triggers.rg} --name ${self.triggers.name} --yes --no-wait || true"
  }

  triggers = {
    rg   = azurerm_resource_group.main.name
    name = "${local.pfx}-aks-norbac-${local.sfx}"
  }
}

# ============================================================================
# TRUE NEGATIVE: AKS with RBAC enabled (default)
# SHOULD NOT DETECT - enableRBAC=true
# ============================================================================

resource "azurerm_kubernetes_cluster" "rbac_enabled" {
  count                             = var.enable_aks_rbac ? 1 : 0
  name                              = "${local.pfx}-aks-rbac-${local.sfx}"
  resource_group_name               = azurerm_resource_group.main.name
  location                          = local.loc
  dns_prefix                        = "${local.pfx}-rbac-${local.sfx}"
  role_based_access_control_enabled = true

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_B2s"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "AKS-RBACEnabled"
  })
}
