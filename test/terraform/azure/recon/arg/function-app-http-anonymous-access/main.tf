# Nebula Azure Function App HTTP Anonymous Access - Testing Infrastructure
# Template: function_app_http_anonymous_access
# Purpose: Deploy Function Apps to validate enricher-based detection of
#          HTTP triggers with anonymous auth level (no function keys required)
#
# KQL Logic:
#   type =~ 'microsoft.web/sites'
#   kind contains 'functionapp'
#   Enricher calls Management API to list functions and parse authLevel from bindings
#
# Cost estimate: ~$0.00/hr
#   - Function App Consumption plan: $0.00/hr (pay-per-execution)
#
# NOTE: The actual anonymous function trigger must be deployed as application code.
#       This TF creates the Function App infrastructure; you must deploy a function
#       with authLevel=anonymous to create a true positive.

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
  pfx = "nbfa" # nebula-function-anonymous
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-function-app-anonymous-testing"
    Environment = "test"
    ManagedBy   = "terraform"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "${local.pfx}-rg-${local.sfx}"
  location = local.loc
  tags     = local.tags
}

resource "azurerm_storage_account" "func" {
  name                     = "${local.pfx}sa${local.sfx}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = local.loc
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

resource "azurerm_service_plan" "func" {
  name                = "${local.pfx}-plan-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  os_type             = "Windows"
  sku_name            = "Y1"
  tags                = local.tags
}

# ============================================================================
# TRUE POSITIVE: Function App intended for anonymous HTTP triggers
# SHOULD DETECT - after deploying a function with authLevel=anonymous
# Deploy a function with authLevel=anonymous:
#   func init --python && func new --template "HTTP trigger" --name HttpAnon
#   Then edit function.json: set "authLevel": "anonymous"
#   func azure functionapp publish <name>
# ============================================================================

resource "azurerm_windows_function_app" "anonymous_triggers" {
  name                       = "${local.pfx}-func-anon-${local.sfx}"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = local.loc
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key
  service_plan_id            = azurerm_service_plan.func.id

  site_config {
  }

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME" = "python"
  }

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "FunctionApp-AnonymousHTTPTriggers"
  })
}

# ============================================================================
# TRUE NEGATIVE: Function App with function-key protected triggers
# SHOULD NOT DETECT - functions use authLevel=function (key required)
# Deploy a function with authLevel=function:
#   func init --python && func new --template "HTTP trigger" --name HttpKeyed
#   Ensure function.json has "authLevel": "function" (default)
#   func azure functionapp publish <name>
# ============================================================================

resource "azurerm_windows_function_app" "keyed_triggers" {
  name                       = "${local.pfx}-func-key-${local.sfx}"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = local.loc
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key
  service_plan_id            = azurerm_service_plan.func.id

  site_config {
  }

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME" = "python"
  }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "FunctionApp-KeyedHTTPTriggers"
  })
}

# ============================================================================
# FALSE POSITIVE RESISTANCE: Web App (not Function App)
# SHOULD NOT DETECT - kind does not contain 'functionapp'
# ============================================================================

resource "azurerm_service_plan" "webapp" {
  name                = "${local.pfx}-webplan-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  os_type             = "Linux"
  sku_name            = "F1"
  tags                = local.tags
}

resource "azurerm_linux_web_app" "not_func" {
  name                = "${local.pfx}-web-notfunc-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  service_plan_id     = azurerm_service_plan.webapp.id

  site_config { always_on = false }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "WebApp-NotFunctionApp"
  })
}
