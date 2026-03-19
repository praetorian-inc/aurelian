// Module: gcp-recon-subdomain-takeover
// Provisions Cloud DNS zones with dangling records for subdomain takeover testing.
//
// ==================== TEST CASES ====================
//
// | #  | Record                        | Type  | Service          | Dangling | Expected Result           |
// |----|-------------------------------|-------|------------------|----------|---------------------------|
// | 1  | storage-dangling.${zone}      | CNAME | Cloud Storage    | YES      | CRITICAL risk             |
// | 2  | run-dangling.${zone}          | CNAME | Cloud Run        | YES      | HIGH risk                 |
// | 3  | appengine-dangling.${zone}    | CNAME | App Engine       | YES      | HIGH risk                 |
// | 4  | ip-orphaned.${zone}           | A     | Compute Engine   | YES      | LOW risk                  |
// | 5  | ns-dangling.${zone}           | NS    | Cloud DNS        | YES      | CRITICAL risk             |
// | 6  | safe-cname.${zone}            | CNAME | (none)           | NO       | No risk                   |
// | 7  | safe-a.${zone}                | A     | (none)           | NO       | No risk                   |

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "s3" {}
}

provider "google" {
  region = var.region
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  prefix = "aur-sdt-${random_string.suffix.result}"
  labels = {
    managed-by = "terraform"
    purpose    = "aurelian-gcp-subdomain-takeover-testing"
  }
}

data "google_project" "current" {}

#==============================================================================
# Cloud DNS Managed Zone (public) — all test records live here
#==============================================================================
resource "google_dns_managed_zone" "test" {
  name        = "${local.prefix}-zone"
  dns_name    = "${local.prefix}.example.com."
  description = "Aurelian subdomain takeover integration test zone"
  labels      = local.labels
}

#==============================================================================
# CASE 1: Dangling CNAME → non-existent Cloud Storage bucket
#==============================================================================
resource "google_dns_record_set" "storage_dangling" {
  managed_zone = google_dns_managed_zone.test.name
  name         = "storage-dangling.${google_dns_managed_zone.test.dns_name}"
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["${local.prefix}-nonexistent-bucket.storage.googleapis.com."]
}

#==============================================================================
# CASE 2: Dangling CNAME → non-existent Cloud Run service
#==============================================================================
resource "google_dns_record_set" "run_dangling" {
  managed_zone = google_dns_managed_zone.test.name
  name         = "run-dangling.${google_dns_managed_zone.test.dns_name}"
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["${local.prefix}-nonexistent-svc-abc123def.a.run.app."]
}

#==============================================================================
# CASE 3: Dangling CNAME → non-existent App Engine app
#==============================================================================
resource "google_dns_record_set" "appengine_dangling" {
  managed_zone = google_dns_managed_zone.test.name
  name         = "appengine-dangling.${google_dns_managed_zone.test.dns_name}"
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["${local.prefix}-nonexistent-app.appspot.com."]
}

#==============================================================================
# CASE 4: Orphaned A record → IP not allocated in the project
# Using a documentation/reserved IP that won't be in any GCP project.
#==============================================================================
resource "google_dns_record_set" "ip_orphaned" {
  managed_zone = google_dns_managed_zone.test.name
  name         = "ip-orphaned.${google_dns_managed_zone.test.dns_name}"
  type         = "A"
  ttl          = 300
  rrdatas      = ["198.51.100.1"]
}

#==============================================================================
# CASE 5: Dangling NS delegation → Cloud DNS nameservers for non-existent zone
#==============================================================================
resource "google_dns_record_set" "ns_dangling" {
  managed_zone = google_dns_managed_zone.test.name
  name         = "ns-dangling.${google_dns_managed_zone.test.dns_name}"
  type         = "NS"
  ttl          = 300
  rrdatas = [
    "ns-cloud-a1.googledomains.com.",
    "ns-cloud-a2.googledomains.com.",
    "ns-cloud-a3.googledomains.com.",
    "ns-cloud-a4.googledomains.com.",
  ]
}

#==============================================================================
# CASE 6: Safe CNAME → non-GCP target (should NOT trigger any finding)
#==============================================================================
resource "google_dns_record_set" "safe_cname" {
  managed_zone = google_dns_managed_zone.test.name
  name         = "safe-cname.${google_dns_managed_zone.test.dns_name}"
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["www.example.com."]
}

#==============================================================================
# CASE 7: Safe A record → private IP (should NOT trigger any finding because
# the checker only flags IPs within the project's compute address space)
#==============================================================================
resource "google_dns_record_set" "safe_a" {
  managed_zone = google_dns_managed_zone.test.name
  name         = "safe-a.${google_dns_managed_zone.test.dns_name}"
  type         = "A"
  ttl          = 300
  rrdatas      = ["192.168.1.1"]
}
