# Nebula Azure App Service Auth Disabled - Testing Infrastructure
# Template: app_service_auth_disabled
# Purpose: Deploy App Services with/without Easy Auth to validate enricher-based detection
#
# KQL Logic:
#   type =~ 'microsoft.web/sites'
#   kind !contains 'functionapp'
#   Enricher calls config/authsettingsV2 to check platform.enabled
#
# Cost estimate: ~$0.00/hr
#   - App Service F1 (Free) tier: $0.00/hr

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
  pfx = "nbau" # nebula-auth
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-app-service-auth-testing"
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
  sku_name            = "F1"
  tags                = local.tags
}

# ============================================================================
# TRUE POSITIVE: App Service without Easy Auth (auth disabled)
# SHOULD DETECT - enricher finds platform.enabled=false
# ============================================================================

resource "azurerm_linux_web_app" "no_auth" {
  name                = "${local.pfx}-app-noauth-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  service_plan_id     = azurerm_service_plan.main.id

  site_config { always_on = false }

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "AppService-AuthDisabled"
  })
}

# ============================================================================
# TRUE NEGATIVE: App Service with Easy Auth enabled
# SHOULD NOT DETECT - enricher finds platform.enabled=true
# NOTE: Enabling auth requires AAD app registration or manual config.
#       This resource is a placeholder; enable auth via Azure Portal or CLI:
#       az webapp auth update -g <rg> -n <name> --enabled true --action LoginWithAzureActiveDirectory
# ============================================================================

resource "azurerm_linux_web_app" "with_auth" {
  name                = "${local.pfx}-app-auth-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  service_plan_id     = azurerm_service_plan.main.id

  site_config { always_on = false }

  # Auth settings v2 - enable built-in authentication
  # Requires at least one identity provider; use AAD with placeholder client ID
  auth_settings_v2 {
    auth_enabled           = true
    require_authentication = true
    unauthenticated_action = "Return401"

    active_directory_v2 {
      client_id            = "00000000-0000-0000-0000-000000000000"
      tenant_auth_endpoint = "https://login.microsoftonline.com/${data.azurerm_client_config.current.tenant_id}/v2.0"
    }

    login {}
  }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "AppService-AuthEnabled"
  })
}

# ============================================================================
# FALSE POSITIVE RESISTANCE: Function App without auth (should not match)
# SHOULD NOT DETECT - kind contains 'functionapp' (excluded by query)
# ============================================================================

resource "azurerm_storage_account" "func" {
  name                     = "${local.pfx}func${local.sfx}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = local.loc
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

resource "azurerm_service_plan" "func" {
  name                = "${local.pfx}-funcplan-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  os_type             = "Windows"
  sku_name            = "Y1"
  tags                = local.tags
}

resource "azurerm_windows_function_app" "no_auth" {
  name                       = "${local.pfx}-func-noauth-${local.sfx}"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = local.loc
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key
  service_plan_id            = azurerm_service_plan.func.id

  site_config {}

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "FunctionApp-NotWebApp-ExcludedByKind"
  })
}
