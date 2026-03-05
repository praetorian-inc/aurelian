# Nebula Azure App Service Remote Debugging - Testing Infrastructure
# Template: app_service_remote_debugging_enabled
# Purpose: Deploy App Services with/without remote debugging to validate enricher detection
#
# KQL Logic:
#   type =~ 'microsoft.web/sites'
#   Enricher checks properties.siteConfig.remoteDebuggingEnabled
#
# Cost estimate: ~$0.02/hr
#   - App Service B1: ~$0.02/hr (required for remote debugging, F1 doesn't support it)

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
  pfx = "nbrd" # nebula-remote-debug
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-app-service-remote-debugging-testing"
    Environment = "test"
    ManagedBy   = "terraform"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "${local.pfx}-rg-${local.sfx}"
  location = local.loc
  tags     = local.tags
}

resource "azurerm_service_plan" "main" {
  name                = "${local.pfx}-asp-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  os_type             = "Linux"
  sku_name            = "B1"
  tags                = local.tags
}

# ============================================================================
# TRUE POSITIVE: App Service with remote debugging enabled
# SHOULD DETECT - remoteDebuggingEnabled=true
# ============================================================================

resource "azurerm_linux_web_app" "debug_enabled" {
  name                = "${local.pfx}-app-dbg-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  service_plan_id     = azurerm_service_plan.main.id

  site_config {
    remote_debugging_enabled = true
    remote_debugging_version = "VS2022"
  }

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "AppService-RemoteDebuggingEnabled"
  })
}

# ============================================================================
# TRUE NEGATIVE: App Service with remote debugging disabled (default)
# SHOULD NOT DETECT - remoteDebuggingEnabled=false
# ============================================================================

resource "azurerm_linux_web_app" "debug_disabled" {
  name                = "${local.pfx}-app-nodbg-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  service_plan_id     = azurerm_service_plan.main.id

  site_config {
    remote_debugging_enabled = false
  }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "AppService-RemoteDebuggingDisabled"
  })
}
