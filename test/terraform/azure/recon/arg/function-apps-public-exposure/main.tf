# Nebula Azure Function Apps Public Exposure - Testing Infrastructure
# Template: function_apps_public_exposure
# Purpose: Deploy Function Apps with/without public access + private endpoints
#
# KQL Logic:
#   type =~ 'microsoft.web/sites'
#   kind contains 'functionapp'
#   publicNetworkAccess defaults to 'Enabled' when null
#   peCount = coalesce(array_length(properties.privateEndpointConnections), 0)
#   hasPrivateEndpoint = peCount > 0
#   where publicNetworkAccess != 'disabled'
#   where hasPrivateEndpoint == false
#
# Cost estimate: ~$0.01/hr
#   - Function App Consumption: $0.00/hr
#   - Private Endpoint: ~$0.01/hr

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
  pfx = "nbfe" # nebula-func-exposure
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-function-apps-public-exposure-testing"
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

resource "azurerm_service_plan" "consumption" {
  name                = "${local.pfx}-conplan-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  os_type             = "Windows"
  sku_name            = "Y1"
  tags                = local.tags
}

# Premium plan needed for private endpoints
resource "azurerm_service_plan" "premium" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = "${local.pfx}-premplan-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  os_type             = "Windows"
  sku_name            = "EP1"
  tags                = local.tags
}

# ============================================================================
# TRUE POSITIVE: Function App with public access, no private endpoint
# SHOULD DETECT - publicNetworkAccess=Enabled, no PE
# ============================================================================

resource "azurerm_windows_function_app" "public_no_pe" {
  name                          = "${local.pfx}-func-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  storage_account_name          = azurerm_storage_account.func.name
  storage_account_access_key    = azurerm_storage_account.func.primary_access_key
  service_plan_id               = azurerm_service_plan.consumption.id
  public_network_access_enabled = true

  site_config {
  }

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "FunctionApp-Public-NoPrivateEndpoint"
  })
}

# ============================================================================
# TRUE NEGATIVE 1: Function App with public access disabled
# SHOULD NOT DETECT - publicNetworkAccess=disabled
# ============================================================================

resource "azurerm_windows_function_app" "private_disabled" {
  name                          = "${local.pfx}-func-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  storage_account_name          = azurerm_storage_account.func.name
  storage_account_access_key    = azurerm_storage_account.func.primary_access_key
  service_plan_id               = azurerm_service_plan.consumption.id
  public_network_access_enabled = false

  site_config {
  }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "FunctionApp-AccessDisabled"
  })
}

# ============================================================================
# TRUE NEGATIVE 2: Function App with public access + private endpoint
# SHOULD NOT DETECT - hasPrivateEndpoint == true
# Requires Premium plan (Consumption doesn't support PE)
# ============================================================================

resource "azurerm_virtual_network" "main" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = "${local.pfx}-vnet-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  address_space       = ["10.0.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "pe" {
  count                = var.enable_private_endpoint ? 1 : 0
  name                 = "private-endpoints"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main[0].name
  address_prefixes     = ["10.0.1.0/24"]

  private_endpoint_network_policies_enabled = true
}

resource "azurerm_windows_function_app" "public_with_pe" {
  count                         = var.enable_private_endpoint ? 1 : 0
  name                          = "${local.pfx}-func-pe-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  storage_account_name          = azurerm_storage_account.func.name
  storage_account_access_key    = azurerm_storage_account.func.primary_access_key
  service_plan_id               = azurerm_service_plan.premium[0].id
  public_network_access_enabled = true

  site_config {
  }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "FunctionApp-Public-WithPrivateEndpoint"
  })
}

resource "azurerm_private_endpoint" "func" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = "${local.pfx}-func-pe-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  subnet_id           = azurerm_subnet.pe[0].id

  private_service_connection {
    name                           = "func-pe-connection"
    private_connection_resource_id = azurerm_windows_function_app.public_with_pe[0].id
    is_manual_connection           = false
    subresource_names              = ["sites"]
  }

  tags = local.tags
}

# ============================================================================
# FALSE POSITIVE RESISTANCE: Web App (not Function App) with public access
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

resource "azurerm_linux_web_app" "public_webapp" {
  name                          = "${local.pfx}-web-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  service_plan_id               = azurerm_service_plan.webapp.id
  public_network_access_enabled = true

  site_config { always_on = false }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "WebApp-NotFunctionApp-Public"
  })
}
