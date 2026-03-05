# Nebula Azure Function Apps Public HTTP Triggers - Testing Infrastructure
# Template: function_apps_public_http_triggers
# Purpose: Deploy function apps with/without public access and IP restrictions,
#          PLUS enricher-level edge cases (deployment slots, EasyAuth, anonymous triggers)
#
# KQL Logic (filter stage):
#   type =~ 'Microsoft.Web/sites'
#   kind contains 'functionapp' AND kind !contains 'workflowapp'
#   publicNetworkAccess = tolower(coalesce(properties.publicNetworkAccess, 'enabled'))
#   where publicNetworkAccess != 'disabled'
#   NOTE: ARG does NOT index siteConfig.ipSecurityRestrictions — IP restriction
#         filtering is handled by the enricher via Management API, not KQL.
#
# Enricher Logic (post-filter via Management API):
#   IP restriction check (ARG can't see this property)
#   Management API enumeration of functions + HTTP trigger auth levels
#   Deployment slot enumeration + trigger enumeration per slot
#   EasyAuth / Entra ID cross-reference as compensating control
#   Anonymous trigger probe with redirect detection
#   SCM/Kudu site exposure check
#
# KQL-Level Tests:
#   TP:  Public function app with no IP restrictions - DETECTED
#   TN:  Function app with publicNetworkAccess=disabled - NOT detected
#
# Enricher-Level Tests:
#   TP-IPR:      Public function app WITH IP restrictions - DETECTED by KQL, enricher notes restrictions
#   TP-SLOT:     Public function app with a deployment slot (tests slot enumeration)
#   TN-EASYAUTH: Public function app with EasyAuth enabled (compensating control - enricher notes it)
#   TP-ANON:     Public function app for anonymous trigger deployment (requires func CLI deploy)
#   TN-KEYED:    Public function app for function-key trigger deployment (requires func CLI deploy)
#
# Cost estimate: ~$0.00/hr (Windows consumption plans, minimal usage)
# NOTE: Uses Windows function apps due to Linux Dynamic SKU subscription restriction
# NOTE: TP-ANON and TN-KEYED require manual function code deployment (see README.md)

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
  pfx = "nbht" # nebula-http-triggers
  sfx = random_string.suffix.result
}

resource "azurerm_resource_group" "main" {
  name     = "${local.pfx}-rg-${local.sfx}"
  location = var.location
  tags = {
    purpose   = "nebula-testing"
    template  = "function_apps_public_http_triggers"
    temporary = "true"
  }
}

resource "azurerm_storage_account" "func" {
  name                     = "${local.pfx}sa${local.sfx}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_service_plan" "func" {
  name                = "${local.pfx}-plan-${local.sfx}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Windows"
  sku_name            = "Y1"
}

# ═══════════════════════════════════════════════════════════════
# TRUE POSITIVE: Public function app with NO IP restrictions
# Should be DETECTED by function_apps_public_http_triggers
# ═══════════════════════════════════════════════════════════════
resource "azurerm_windows_function_app" "public_no_restrictions" {
  count = var.enable_tp ? 1 : 0

  name                       = "${local.pfx}-pub-${local.sfx}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  service_plan_id            = azurerm_service_plan.func.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key

  public_network_access_enabled = true

  site_config {}

  tags = {
    test_case = "TP"
    expected  = "detected"
  }
}

# ═══════════════════════════════════════════════════════════════
# TRUE NEGATIVE 1: Function app with public network access DISABLED
# Should NOT be detected (publicNetworkAccess == 'disabled')
# ═══════════════════════════════════════════════════════════════
resource "azurerm_windows_function_app" "private" {
  count = var.enable_tn_private ? 1 : 0

  name                       = "${local.pfx}-prv-${local.sfx}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  service_plan_id            = azurerm_service_plan.func.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key

  public_network_access_enabled = false

  site_config {}

  tags = {
    test_case = "TN-private"
    expected  = "not_detected"
  }
}

# ═══════════════════════════════════════════════════════════════
# ENRICHER TEST: Public function app WITH IP restrictions
# KQL: DETECTED (public, ARG does NOT index ipSecurityRestrictions)
# Enricher: Should detect IP restrictions via Management API and
#           report them as a compensating control (lower severity)
# ═══════════════════════════════════════════════════════════════
resource "azurerm_windows_function_app" "public_ip_restricted" {
  count = var.enable_tn_restricted ? 1 : 0

  name                       = "${local.pfx}-ipr-${local.sfx}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  service_plan_id            = azurerm_service_plan.func.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key

  public_network_access_enabled = true

  site_config {
    ip_restriction {
      ip_address = "10.0.0.0/8"
      action     = "Allow"
      name       = "allow-internal"
      priority   = 100
    }
  }

  tags = {
    test_case = "TP-ip-restricted"
    expected  = "detected_kql_enricher_notes_ip_restrictions"
  }
}

# ═══════════════════════════════════════════════════════════════
# ENRICHER TEST: Public function app WITH deployment slot
# KQL: DETECTED (public, no IP restrictions — same as TP)
# Enricher: Should enumerate both production AND staging slot triggers
# ═══════════════════════════════════════════════════════════════
resource "azurerm_windows_function_app" "with_slot" {
  count = var.enable_tp_slot ? 1 : 0

  name                       = "${local.pfx}-slot-${local.sfx}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  service_plan_id            = azurerm_service_plan.slot.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key

  public_network_access_enabled = true

  site_config {}

  tags = {
    test_case = "TP-slot"
    expected  = "detected_with_slot_enumeration"
  }
}

# Deployment slot — the enricher should discover this via NewListSlotsPager
resource "azurerm_windows_function_app_slot" "staging" {
  count = var.enable_tp_slot ? 1 : 0

  name                       = "staging"
  function_app_id            = azurerm_windows_function_app.with_slot[0].id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key

  site_config {}

  tags = {
    test_case = "TP-slot-staging"
    expected  = "enumerated_by_enricher"
  }
}

# Deployment slots require Standard tier or higher (Y1 does not support slots)
resource "azurerm_service_plan" "slot" {
  name                = "${local.pfx}-slot-plan-${local.sfx}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Windows"
  sku_name            = "S1"
}

# ═══════════════════════════════════════════════════════════════
# ENRICHER TEST: Public function app WITH EasyAuth enabled
# KQL: DETECTED (public, no IP restrictions — same as TP)
# Enricher: Should detect EasyAuth as a compensating control
#   and note that anonymous triggers are overridden by platform auth
# ═══════════════════════════════════════════════════════════════
resource "azurerm_windows_function_app" "easyauth" {
  count = var.enable_tn_easyauth ? 1 : 0

  name                       = "${local.pfx}-auth-${local.sfx}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  service_plan_id            = azurerm_service_plan.func.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key

  public_network_access_enabled = true

  site_config {}

  auth_settings_v2 {
    auth_enabled           = true
    require_authentication = true
    unauthenticated_action = "RedirectToLoginPage"
    default_provider       = "azureactivedirectory"

    active_directory_v2 {
      client_id            = "00000000-0000-0000-0000-000000000000"
      tenant_auth_endpoint = "https://login.microsoftonline.com/${data.azurerm_client_config.current.tenant_id}/v2.0"
    }

    login {
      token_store_enabled = true
    }
  }

  tags = {
    test_case = "TN-easyauth"
    expected  = "detected_kql_but_easyauth_compensating"
  }
}

# ═══════════════════════════════════════════════════════════════
# ENRICHER TEST: Public function app for anonymous trigger deployment
# KQL: DETECTED (public, no IP restrictions)
# Enricher: After func CLI deployment with authLevel=anonymous,
#   should detect anonymous HTTP trigger and probe invoke URL
#
# REQUIRES MANUAL STEP: Deploy a function with authLevel=anonymous
#   See README.md for instructions
# ═══════════════════════════════════════════════════════════════
resource "azurerm_windows_function_app" "anonymous_trigger" {
  count = var.enable_tp_anonymous ? 1 : 0

  name                       = "${local.pfx}-anon-${local.sfx}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  service_plan_id            = azurerm_service_plan.func.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key

  public_network_access_enabled = true

  site_config {}

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME" = "dotnet-isolated"
  }

  tags = {
    test_case = "TP-anonymous-trigger"
    expected  = "detected_anonymous_http_trigger"
  }
}

# ═══════════════════════════════════════════════════════════════
# ENRICHER TEST: Public function app for function-key trigger deployment
# KQL: DETECTED (public, no IP restrictions)
# Enricher: After func CLI deployment with authLevel=function,
#   should enumerate triggers but NOT flag as anonymous
#
# REQUIRES MANUAL STEP: Deploy a function with authLevel=function
#   See README.md for instructions
# ═══════════════════════════════════════════════════════════════
resource "azurerm_windows_function_app" "keyed_trigger" {
  count = var.enable_tn_keyed ? 1 : 0

  name                       = "${local.pfx}-key-${local.sfx}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  service_plan_id            = azurerm_service_plan.func.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key

  public_network_access_enabled = true

  site_config {}

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME" = "dotnet-isolated"
  }

  tags = {
    test_case = "TN-keyed-trigger"
    expected  = "detected_kql_but_no_anonymous_triggers"
  }
}
