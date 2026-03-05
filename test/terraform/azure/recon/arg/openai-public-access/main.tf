# Nebula Azure OpenAI Public Access - Testing Infrastructure
# Template: openai_public_access
# Purpose: Deploy OpenAI Cognitive Services resources to validate Nebula detection
#          of publicly accessible OpenAI endpoints without private endpoints.
#
# KQL Logic:
#   type =~ 'microsoft.cognitiveservices/accounts'
#   kind =~ 'OpenAI'
#   publicNetworkAccess defaults to 'Enabled' when null
#   hasPrivateEndpoint == false (no privateEndpointConnections)
#
# Cost estimate: ~$0.00/hr (OpenAI accounts are free until inference usage)
#   - Cognitive Services accounts: Free to create (pay-per-use on inference)
#   - Private Endpoint: ~$0.01/hr
#   - VNet: Free

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
  pfx = "nboi" # nebula-openai
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-openai-public-access-testing"
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
# NETWORKING (for private endpoint TN)
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

# ============================================================================
# TRUE POSITIVE: OpenAI with public access, no private endpoint
# SHOULD DETECT - publicNetworkAccess=Enabled, no PE connections
# ============================================================================

resource "azurerm_cognitive_account" "openai_public" {
  name                          = "${local.pfx}-oai-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = var.openai_location
  kind                          = "OpenAI"
  sku_name                      = "S0"
  custom_subdomain_name         = "${local.pfx}-oai-pub-${local.sfx}"
  public_network_access_enabled = true

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "OpenAI-Public-NoPrivateEndpoint"
  })
}

# ============================================================================
# TRUE NEGATIVE 1: OpenAI with public access DISABLED
# SHOULD NOT DETECT - publicNetworkAccess=Disabled
# ============================================================================

resource "azurerm_cognitive_account" "openai_private_disabled" {
  name                          = "${local.pfx}-oai-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = var.openai_location
  kind                          = "OpenAI"
  sku_name                      = "S0"
  custom_subdomain_name         = "${local.pfx}-oai-prv-${local.sfx}"
  public_network_access_enabled = false

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "OpenAI-Private-AccessDisabled"
  })
}

# ============================================================================
# TRUE NEGATIVE 2: OpenAI with public access + private endpoint
# SHOULD NOT DETECT - hasPrivateEndpoint == true
# ============================================================================

resource "azurerm_cognitive_account" "openai_with_pe" {
  count                         = var.enable_private_endpoint ? 1 : 0
  name                          = "${local.pfx}-oai-pe-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = var.openai_location
  kind                          = "OpenAI"
  sku_name                      = "S0"
  custom_subdomain_name         = "${local.pfx}-oai-pe-${local.sfx}"
  public_network_access_enabled = true

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "OpenAI-Public-WithPrivateEndpoint"
  })
}

resource "azurerm_private_endpoint" "openai" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = "${local.pfx}-oai-pe-${local.sfx}"
  resource_group_name = azurerm_resource_group.main.name
  location            = local.loc
  subnet_id           = azurerm_subnet.pe[0].id

  private_service_connection {
    name                           = "oai-pe-connection"
    private_connection_resource_id = azurerm_cognitive_account.openai_with_pe[0].id
    is_manual_connection           = false
    subresource_names              = ["account"]
  }

  tags = local.tags
}

# ============================================================================
# FALSE POSITIVE RESISTANCE: Non-OpenAI Cognitive Service (public, no PE)
# SHOULD NOT DETECT - kind != 'OpenAI' (TextAnalytics instead)
# ============================================================================

resource "azurerm_cognitive_account" "text_analytics_public" {
  name                          = "${local.pfx}-ta-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  kind                          = "TextAnalytics"
  sku_name                      = "S"
  custom_subdomain_name         = "${local.pfx}-ta-pub-${local.sfx}"
  public_network_access_enabled = true

  network_acls { default_action = "Allow" }

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "TextAnalytics-Public-NotOpenAI"
  })
}

# ============================================================================
# FALSE POSITIVE RESISTANCE: Non-OpenAI Cognitive Service (FormRecognizer)
# SHOULD NOT DETECT - kind != 'OpenAI'
# ============================================================================

resource "azurerm_cognitive_account" "form_recognizer_public" {
  name                          = "${local.pfx}-fr-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  kind                          = "FormRecognizer"
  sku_name                      = "S0"
  custom_subdomain_name         = "${local.pfx}-fr-pub-${local.sfx}"
  public_network_access_enabled = true

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "FormRecognizer-Public-NotOpenAI"
  })
}
