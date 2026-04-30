output "subscription_id" {
  value = var.subscription_id
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

output "expected_unauthenticated_apis" {
  description = "APIs the apim-missing-auth module should flag"
  value = [
    "${azurerm_api_management.apim1.id}/apis/${azurerm_api_management_api.unauth.name}",
  ]
}

output "expected_direct_access_backends" {
  description = "Backends the apim-backend-direct-access module should flag as high"
  value = [
    azurerm_api_management_backend.public_app.url,
  ]
}
