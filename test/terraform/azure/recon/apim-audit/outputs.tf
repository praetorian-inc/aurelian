output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "resource_group" {
  value = azurerm_resource_group.test.name
}

output "apim1_id" {
  value = azurerm_api_management.apim1.id
}

output "apim2_id" {
  value = azurerm_api_management.apim2.id
}

output "public_app_service_hostname" {
  value = azurerm_linux_web_app.public_backend.default_hostname
}

output "public_app_service_id" {
  value = azurerm_linux_web_app.public_backend.id
}

# Per-API IDs — used by integration tests to assert positive vs negative cases
# precisely without depending on string concatenation in the test code.

# Per-API DedupIDs use the format <service_resource_id>/<api_name>, matching
# how the apim-audit module emits AurelianRisk.DeduplicationID.

output "unauth_api_id" {
  description = "API expected to be flagged azure-apim-missing-auth (no auth at any scope)"
  value       = "${azurerm_api_management.apim1.id}/${azurerm_api_management_api.unauth.name}"
}

output "fake_mcp_api_id" {
  description = "API expected to be flagged azure-apim-mcp-missing-auth (MCP-shaped, no auth)"
  value       = "${azurerm_api_management.apim1.id}/${azurerm_api_management_api.fake_mcp.name}"
}

output "jwt_api_id" {
  description = "API protected by API-scope validate-jwt — must NOT be flagged"
  value       = "${azurerm_api_management.apim1.id}/${azurerm_api_management_api.jwt.name}"
}

output "ipfilter_api_id" {
  description = "API protected by API-scope ip-filter — must NOT be flagged"
  value       = "${azurerm_api_management.apim1.id}/${azurerm_api_management_api.ipfilter.name}"
}

output "checkheader_api_id" {
  description = "API protected by API-scope check-header — must NOT be flagged"
  value       = "${azurerm_api_management.apim1.id}/${azurerm_api_management_api.checkheader.name}"
}

output "product_auth_api_id" {
  description = "API protected by product-scope JWT + subscription-required — must NOT be flagged"
  value       = "${azurerm_api_management.apim1.id}/${azurerm_api_management_api.product_auth.name}"
}

output "inherits_auth_api_id" {
  description = "API on apim2 inheriting service-scope validate-jwt — must NOT be flagged"
  value       = "${azurerm_api_management.apim2.id}/${azurerm_api_management_api.inherits_auth.name}"
}

output "public_backend_name" {
  description = "APIM backend pointing at the public App Service — expected azure-apim-backend-direct-access High"
  value       = azurerm_api_management_backend.public_app.name
}

output "public_backend_url" {
  description = "URL of the APIM backend pointing at the public App Service"
  value       = azurerm_api_management_backend.public_app.url
}
