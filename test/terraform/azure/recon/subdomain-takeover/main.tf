terraform {
  backend "s3" {}

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  prefix     = "${var.prefix}-${random_string.suffix.result}"
  prefix_san = "${var.prefix}${random_string.suffix.result}"
}

resource "azurerm_resource_group" "test" {
  name     = "${local.prefix}-rg"
  location = "East US"
}

resource "azurerm_dns_zone" "test" {
  name                = "${local.prefix}.example.com"
  resource_group_name = azurerm_resource_group.test.name
}

# Test cases:
# | Record            | Type  | Service          | Expected Finding          |
# |-------------------|-------|------------------|---------------------------|
# | appsvc-dangling   | CNAME | App Service      | appsvc-subdomain-takeover |
# | storage-dangling  | CNAME | Blob Storage     | storage-subdomain-takeover|
# | tm-dangling       | CNAME | Traffic Manager  | trafficmgr-subdomain-takeover |
# | cdn-dangling      | CNAME | CDN Classic      | cdn-subdomain-takeover    |
# | orphaned-ip       | A     | Public IP        | orphaned-ip-a-record      |
# | dangling-ns       | NS    | Azure DNS        | ns-delegation-takeover    |
# | safe-cname        | CNAME | (none)           | No finding                |
# | safe-a            | A     | (none - private) | No finding                |

# Dangling App Service CNAME — points to non-existent app
resource "azurerm_dns_cname_record" "appsvc_dangling" {
  name                = "appsvc-dangling"
  zone_name           = azurerm_dns_zone.test.name
  resource_group_name = azurerm_resource_group.test.name
  ttl                 = 300
  record              = "${local.prefix}-nonexistent-app.azurewebsites.net"
}

# Dangling Storage CNAME — points to non-existent storage account
resource "azurerm_dns_cname_record" "storage_dangling" {
  name                = "storage-dangling"
  zone_name           = azurerm_dns_zone.test.name
  resource_group_name = azurerm_resource_group.test.name
  ttl                 = 300
  record              = "${local.prefix_san}noexist.blob.core.windows.net"
}

# Dangling Traffic Manager CNAME
resource "azurerm_dns_cname_record" "trafficmgr_dangling" {
  name                = "tm-dangling"
  zone_name           = azurerm_dns_zone.test.name
  resource_group_name = azurerm_resource_group.test.name
  ttl                 = 300
  record              = "${local.prefix}-nonexistent-tm.trafficmanager.net"
}

# Dangling CDN CNAME
resource "azurerm_dns_cname_record" "cdn_dangling" {
  name                = "cdn-dangling"
  zone_name           = azurerm_dns_zone.test.name
  resource_group_name = azurerm_resource_group.test.name
  ttl                 = 300
  record              = "${local.prefix}-nonexistent-cdn.azureedge.net"
}

# Orphaned IP A record — documentation IP, guaranteed not allocated
resource "azurerm_dns_a_record" "orphaned_ip" {
  name                = "orphaned-ip"
  zone_name           = azurerm_dns_zone.test.name
  resource_group_name = azurerm_resource_group.test.name
  ttl                 = 300
  records             = ["198.51.100.1"]
}

# NS delegation to Azure DNS nameservers (non-existent zone)
resource "azurerm_dns_ns_record" "dangling_ns" {
  name                = "dangling-ns"
  zone_name           = azurerm_dns_zone.test.name
  resource_group_name = azurerm_resource_group.test.name
  ttl                 = 300
  records = [
    "ns1-01.azure-dns.com.",
    "ns2-01.azure-dns.net.",
    "ns3-01.azure-dns.org.",
    "ns4-01.azure-dns.info.",
  ]
}

# Safe CNAME — points to external target (should NOT trigger)
resource "azurerm_dns_cname_record" "safe_cname" {
  name                = "safe-cname"
  zone_name           = azurerm_dns_zone.test.name
  resource_group_name = azurerm_resource_group.test.name
  ttl                 = 300
  record              = "www.example.com"
}

# Safe A record — private IP (should NOT trigger)
resource "azurerm_dns_a_record" "safe_a" {
  name                = "safe-a"
  zone_name           = azurerm_dns_zone.test.name
  resource_group_name = azurerm_resource_group.test.name
  ttl                 = 300
  records             = ["192.168.1.1"]
}
