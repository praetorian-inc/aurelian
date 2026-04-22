# Aurelian integration fixture for the apim-missing-auth recon module.
#
# ============================= TEST MATRIX =============================
#
#   | API                     | Policies configured                              | Expected verdict        |
#   |-------------------------|--------------------------------------------------|-------------------------|
#   | apim-1/unauth-api       | none                                             | UNAUTHENTICATED (emit)  |
#   | apim-1/jwt-api          | API-scope <validate-jwt>                         | authenticated (skip)    |
#   | apim-1/ipfilter-api     | API-scope <ip-filter>                            | authenticated (skip)    |
#   | apim-1/checkheader-api  | API-scope <check-header name="Authorization">    | authenticated (skip)    |
#   | apim-1/product-auth-api | no API policy; SubscriptionRequired=true; member | authenticated (skip)    |
#   |                         | of product with <validate-jwt> policy            |                         |
#   | apim-2/inherits-auth-api| no API policy; service-scope <validate-jwt>      | authenticated (skip)    |

terraform {
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
}

provider "azurerm" {
  subscription_id = var.subscription_id
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  prefix = "aur-apim-${random_string.suffix.result}"
  tags = {
    ManagedBy = "terraform"
    Purpose   = "aurelian-apim-missing-auth-testing"
  }
}

resource "azurerm_resource_group" "test" {
  name     = "${local.prefix}-rg"
  location = var.location
  tags     = local.tags
}

# ============================================================
# APIM #1 — per-API policies (Consumption tier, free)
# ============================================================
resource "azurerm_api_management" "apim1" {
  name                = "${local.prefix}-1"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  publisher_name      = "Aurelian Testing"
  publisher_email     = "test@example.com"
  sku_name            = "Consumption_0"
  tags                = local.tags
}

# ---------- API: unauth-api (positive case — no auth anywhere) ----------
resource "azurerm_api_management_api" "unauth" {
  name                = "unauth-api"
  resource_group_name = azurerm_resource_group.test.name
  api_management_name = azurerm_api_management.apim1.name
  revision            = "1"
  display_name        = "Unauthenticated API"
  path                = "unauth"
  protocols           = ["https"]
  # No SubscriptionRequired; azurerm defaults to true — override to false to
  # match the finding's "fully open" endpoint shape.
  subscription_required = false
}

# ---------- API: jwt-api (negative — API-scope validate-jwt) ----------
resource "azurerm_api_management_api" "jwt" {
  name                  = "jwt-api"
  resource_group_name   = azurerm_resource_group.test.name
  api_management_name   = azurerm_api_management.apim1.name
  revision              = "1"
  display_name          = "JWT Authenticated API"
  path                  = "jwt"
  protocols             = ["https"]
  subscription_required = false
}

resource "azurerm_api_management_api_policy" "jwt" {
  api_name            = azurerm_api_management_api.jwt.name
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name

  xml_content = <<-XML
    <policies>
      <inbound>
        <base />
        <validate-jwt header-name="Authorization" failed-validation-httpcode="401" require-scheme="Bearer">
          <openid-config url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" />
        </validate-jwt>
      </inbound>
      <backend><base /></backend>
      <outbound><base /></outbound>
      <on-error><base /></on-error>
    </policies>
  XML
}

# ---------- API: ipfilter-api (negative — API-scope ip-filter) ----------
resource "azurerm_api_management_api" "ipfilter" {
  name                  = "ipfilter-api"
  resource_group_name   = azurerm_resource_group.test.name
  api_management_name   = azurerm_api_management.apim1.name
  revision              = "1"
  display_name          = "IP-Filtered API"
  path                  = "ipf"
  protocols             = ["https"]
  subscription_required = false
}

resource "azurerm_api_management_api_policy" "ipfilter" {
  api_name            = azurerm_api_management_api.ipfilter.name
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name

  xml_content = <<-XML
    <policies>
      <inbound>
        <base />
        <ip-filter action="allow">
          <address-range from="10.0.0.0" to="10.255.255.255" />
        </ip-filter>
      </inbound>
      <backend><base /></backend>
      <outbound><base /></outbound>
      <on-error><base /></on-error>
    </policies>
  XML
}

# ---------- API: checkheader-api (negative — check-header Authorization) ----------
resource "azurerm_api_management_api" "checkheader" {
  name                  = "checkheader-api"
  resource_group_name   = azurerm_resource_group.test.name
  api_management_name   = azurerm_api_management.apim1.name
  revision              = "1"
  display_name          = "Check-Header Authenticated API"
  path                  = "chk"
  protocols             = ["https"]
  subscription_required = false
}

resource "azurerm_api_management_api_policy" "checkheader" {
  api_name            = azurerm_api_management_api.checkheader.name
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name

  xml_content = <<-XML
    <policies>
      <inbound>
        <base />
        <check-header name="Authorization" failed-check-httpcode="401" failed-check-error-message="Unauthorized" ignore-case="true">
          <value>Bearer</value>
        </check-header>
      </inbound>
      <backend><base /></backend>
      <outbound><base /></outbound>
      <on-error><base /></on-error>
    </policies>
  XML
}

# ---------- Product: jwt-product with validate-jwt policy ----------
resource "azurerm_api_management_product" "jwt_product" {
  product_id            = "jwt-product"
  api_management_name   = azurerm_api_management.apim1.name
  resource_group_name   = azurerm_resource_group.test.name
  display_name          = "JWT-Authenticated Product"
  subscription_required = true
  approval_required     = false
  published             = true
}

resource "azurerm_api_management_product_policy" "jwt_product" {
  product_id          = azurerm_api_management_product.jwt_product.product_id
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name

  xml_content = <<-XML
    <policies>
      <inbound>
        <base />
        <validate-jwt header-name="Authorization" failed-validation-httpcode="401" require-scheme="Bearer">
          <openid-config url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" />
        </validate-jwt>
      </inbound>
      <backend><base /></backend>
      <outbound><base /></outbound>
      <on-error><base /></on-error>
    </policies>
  XML
}

# ---------- API: product-auth-api (negative — product-scope auth, sub-required=true) ----------
resource "azurerm_api_management_api" "product_auth" {
  name                  = "product-auth-api"
  resource_group_name   = azurerm_resource_group.test.name
  api_management_name   = azurerm_api_management.apim1.name
  revision              = "1"
  display_name          = "Product-Auth API"
  path                  = "prod"
  protocols             = ["https"]
  subscription_required = true
}

resource "azurerm_api_management_product_api" "product_auth" {
  api_name            = azurerm_api_management_api.product_auth.name
  product_id          = azurerm_api_management_product.jwt_product.product_id
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name
}

# ============================================================
# APIM #2 — service-scope validate-jwt (Consumption tier, free)
# ============================================================
resource "azurerm_api_management" "apim2" {
  name                = "${local.prefix}-2"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  publisher_name      = "Aurelian Testing"
  publisher_email     = "test@example.com"
  sku_name            = "Consumption_0"
  tags                = local.tags
}

resource "azurerm_api_management_policy" "apim2_global" {
  api_management_id = azurerm_api_management.apim2.id

  xml_content = <<-XML
    <policies>
      <inbound>
        <validate-jwt header-name="Authorization" failed-validation-httpcode="401" require-scheme="Bearer">
          <openid-config url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" />
        </validate-jwt>
      </inbound>
      <backend><forward-request /></backend>
      <outbound />
      <on-error />
    </policies>
  XML
}

# ---------- API under APIM #2: inherits service-scope auth (negative) ----------
resource "azurerm_api_management_api" "inherits_auth" {
  name                  = "inherits-auth-api"
  resource_group_name   = azurerm_resource_group.test.name
  api_management_name   = azurerm_api_management.apim2.name
  revision              = "1"
  display_name          = "Inherits Service-Scope Auth"
  path                  = "inh"
  protocols             = ["https"]
  subscription_required = false
}
