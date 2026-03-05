# Nebula Azure Event Grid Public Access (Domains) - Testing Infrastructure
# Template: event_grid_domain_public
# Purpose: Deploy Event Grid Domains with/without public access to validate detection
#
# KQL Logic:
#   type == "microsoft.eventgrid/domains"
#   publicNetworkAccess != "Disabled"
#   Categorizes: public with no IP restrictions, public with IP restrictions
#
# Cost estimate: ~$0.00/hr
#   - Event Grid Domains: Free to create (pay per operation)

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
  pfx = "nbeg" # nebula-event-grid
  sfx = random_string.suffix.result
  loc = var.location

  tags = {
    Purpose     = "nebula-event-grid-public-access-testing"
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
# TRUE POSITIVE 1: Event Grid Domain with public access, no IP restrictions
# SHOULD DETECT - publicNetworkAccess=Enabled, no inboundIpRules
# ============================================================================

resource "azurerm_eventgrid_domain" "public_no_ip" {
  name                          = "${local.pfx}-egd-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  public_network_access_enabled = true

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "EventGridDomain-Public-NoIPRestrictions"
  })
}

# ============================================================================
# TRUE POSITIVE 2: Event Grid Domain with public access + IP restrictions
# SHOULD DETECT - publicNetworkAccess=Enabled (with IP restrictions, still public)
# ============================================================================

resource "azurerm_eventgrid_domain" "public_with_ip" {
  name                          = "${local.pfx}-egd-ipr-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  public_network_access_enabled = true

  inbound_ip_rule {
    ip_mask = "10.0.0.0/8"
    action  = "Allow"
  }

  tags = merge(local.tags, {
    ExpectedFind = "true"
    ResourceType = "EventGridDomain-Public-WithIPRestrictions"
  })
}

# ============================================================================
# TRUE NEGATIVE: Event Grid Domain with public access disabled
# SHOULD NOT DETECT - publicNetworkAccess=Disabled
# ============================================================================

resource "azurerm_eventgrid_domain" "private" {
  name                          = "${local.pfx}-egd-prv-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  public_network_access_enabled = false

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "EventGridDomain-Private"
  })
}

# ============================================================================
# FALSE POSITIVE RESISTANCE: Event Grid Topic (not Domain)
# SHOULD NOT DETECT - type is eventgrid/topics, not eventgrid/domains
# ============================================================================

resource "azurerm_eventgrid_topic" "public" {
  name                          = "${local.pfx}-egt-pub-${local.sfx}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = local.loc
  public_network_access_enabled = true

  tags = merge(local.tags, {
    ExpectedFind = "false"
    ResourceType = "EventGridTopic-NotDomain"
  })
}
