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

# ============================================================
# Catch-all GET operations + mock-response op policies so each API
# has something to answer with when curl'd. The mock runs at the
# operation scope, so it only fires if the API/service/product-scope
# inbound policies don't already short-circuit the pipeline.
# ============================================================
locals {
  http_check_apis = {
    unauth      = azurerm_api_management_api.unauth.name
    jwt         = azurerm_api_management_api.jwt.name
    ipfilter    = azurerm_api_management_api.ipfilter.name
    checkheader = azurerm_api_management_api.checkheader.name
    product     = azurerm_api_management_api.product_auth.name
  }
}

resource "azurerm_api_management_api_operation" "get_root" {
  for_each            = local.http_check_apis
  operation_id        = "get-root"
  api_name            = each.value
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name
  display_name        = "Get /"
  method              = "GET"
  url_template        = "/"
  description         = "Catch-all for manual verification"
}

resource "azurerm_api_management_api_operation_policy" "get_root_mock" {
  for_each            = local.http_check_apis
  api_name            = each.value
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name
  operation_id        = azurerm_api_management_api_operation.get_root[each.key].operation_id

  xml_content = <<-XML
    <policies>
      <inbound>
        <base />
        <mock-response status-code="200" content-type="application/json" />
      </inbound>
      <backend><base /></backend>
      <outbound><base /></outbound>
      <on-error><base /></on-error>
    </policies>
  XML
}

resource "azurerm_api_management_api_operation" "inherits_get_root" {
  operation_id        = "get-root"
  api_name            = azurerm_api_management_api.inherits_auth.name
  api_management_name = azurerm_api_management.apim2.name
  resource_group_name = azurerm_resource_group.test.name
  display_name        = "Get /"
  method              = "GET"
  url_template        = "/"
  description         = "Catch-all for manual verification"
}

resource "azurerm_api_management_api_operation_policy" "inherits_get_root_mock" {
  api_name            = azurerm_api_management_api.inherits_auth.name
  api_management_name = azurerm_api_management.apim2.name
  resource_group_name = azurerm_resource_group.test.name
  operation_id        = azurerm_api_management_api_operation.inherits_get_root.operation_id

  xml_content = <<-XML
    <policies>
      <inbound>
        <base />
        <mock-response status-code="200" content-type="application/json" />
      </inbound>
      <backend><base /></backend>
      <outbound><base /></outbound>
      <on-error><base /></on-error>
    </policies>
  XML
}

# ============================================================
# Fake MCP-shaped API on APIM #1 — no authentication, operations
# match the Streamable HTTP MCP transport (/mcp) AND the deprecated
# SSE transport (/sse + /messages). Consumption tier cannot create a
# native MCP-type API, so we synthesize one with the same operation
# shape to exercise the detection logic.
# ============================================================
resource "azurerm_api_management_api" "fake_mcp" {
  name                  = "fake-mcp-api"
  resource_group_name   = azurerm_resource_group.test.name
  api_management_name   = azurerm_api_management.apim1.name
  revision              = "1"
  display_name          = "Fake MCP Server (unauthenticated)"
  path                  = "fake-mcp"
  protocols             = ["https"]
  subscription_required = false
}

resource "azurerm_api_management_api_operation" "fake_mcp_streamable" {
  operation_id        = "mcp-streamable"
  api_name            = azurerm_api_management_api.fake_mcp.name
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name
  display_name        = "MCP Streamable HTTP endpoint"
  method              = "POST"
  url_template        = "/mcp"
  description         = "Streamable-HTTP MCP transport"
}

resource "azurerm_api_management_api_operation_policy" "fake_mcp_streamable_mock" {
  api_name            = azurerm_api_management_api.fake_mcp.name
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name
  operation_id        = azurerm_api_management_api_operation.fake_mcp_streamable.operation_id

  xml_content = <<-XML
    <policies>
      <inbound>
        <base />
        <mock-response status-code="200" content-type="application/json" />
      </inbound>
      <backend><base /></backend>
      <outbound><base /></outbound>
      <on-error><base /></on-error>
    </policies>
  XML
}

resource "azurerm_api_management_api_operation" "fake_mcp_sse" {
  operation_id        = "mcp-sse"
  api_name            = azurerm_api_management_api.fake_mcp.name
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name
  display_name        = "MCP SSE endpoint"
  method              = "GET"
  url_template        = "/sse"
  description         = "Deprecated SSE MCP transport"
}

resource "azurerm_api_management_api_operation" "fake_mcp_messages" {
  operation_id        = "mcp-messages"
  api_name            = azurerm_api_management_api.fake_mcp.name
  api_management_name = azurerm_api_management.apim1.name
  resource_group_name = azurerm_resource_group.test.name
  display_name        = "MCP SSE message channel"
  method              = "POST"
  url_template        = "/messages"
  description         = "SSE message channel"
}
