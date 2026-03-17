output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "resource_group" {
  value = azurerm_resource_group.test.name
}

output "zone_name" {
  value = azurerm_dns_zone.test.name
}

output "appsvc_cname_record" {
  value = azurerm_dns_cname_record.appsvc_dangling.name
}

output "storage_cname_record" {
  value = azurerm_dns_cname_record.storage_dangling.name
}

output "trafficmgr_cname_record" {
  value = azurerm_dns_cname_record.trafficmgr_dangling.name
}

output "cdn_cname_record" {
  value = azurerm_dns_cname_record.cdn_dangling.name
}

output "orphaned_ip_record" {
  value = azurerm_dns_a_record.orphaned_ip.name
}

output "orphaned_ip" {
  value = one(azurerm_dns_a_record.orphaned_ip.records)
}

output "ns_record" {
  value = azurerm_dns_ns_record.dangling_ns.name
}

output "safe_cname_record" {
  value = azurerm_dns_cname_record.safe_cname.name
}

output "safe_a_record" {
  value = azurerm_dns_a_record.safe_a.name
}
