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
// | 8  | ns-child-same.${zone}         | NS    | Cloud DNS        | NO       | No risk                   |
// | 9  | ns-child-other.${zone}        | NS    | Cloud DNS        | NO       | No risk (both projects)   |
// | 10 | ns-deep.${zone}               | NS    | Cloud DNS        | YES      | CRITICAL risk             |
// | 11 | ${zone} (apex NS, implicit)   | NS    | Cloud DNS        | NO       | No risk                   |
// | 12 | zz-paged.${zone}              | NS    | Cloud DNS        | NO       | No risk (paged listing)   |
//
// Cases 8-12 exercise ENG-8964 (checkNS zone-ownership defects):
//   8  - delegated child zone EXISTS in the SAME project -> ownership baseline.
//   9  - delegated child zone EXISTS in a SECOND project -> the reported bug.
//        Requires TF_VAR_secondary_project_id; not provisioned (count = 0) when
//        that variable is unset.
//   10 - only a DEEPER zone (internal.ns-deep.${zone}) exists, while the
//        delegated name itself has no zone -> must still be reported.
//   11 - every Cloud DNS zone gets an apex NS record set automatically. It is
//        the zone's own delegation, not a delegation to a child zone, so it must
//        never be reported. No Terraform resource is needed for this case.
//   12 - delegated child zone EXISTS in the SAME project but sorts PAST the
//        first page of dns.managedZones.list. Requires TF_VAR_filler_zone_count
//        (0 disables, otherwise >= 101); not provisioned (count = 0) by default.
//        Read the cost warning next to the case-12 resources before enabling it.

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

// Case 9 only. Left unconfigured (project = "") when TF_VAR_secondary_project_id
// is unset; no resource targets it in that case, so the rest of the fixture
// still applies cleanly.
provider "google" {
  alias   = "secondary"
  project = var.secondary_project_id
  region  = var.region
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

#==============================================================================
# CASE 8: NS delegation -> child zone that EXISTS in the SAME project
#
# Ownership baseline. The delegated name has a real Cloud DNS zone in the
# project being scanned, so the delegation is not dangling and no risk is
# expected. The NS rrdatas are the child zone's real `name_servers`, not
# hardcoded ns-cloud-a1..a4 values, so the record matches what GCP publishes.
#==============================================================================
resource "google_dns_managed_zone" "ns_child_same_project" {
  name        = "${local.prefix}-child-same"
  dns_name    = "ns-child-same.${google_dns_managed_zone.test.dns_name}"
  description = "Aurelian ENG-8964 case 8: delegated child zone in the same project"
  labels      = local.labels
}

resource "google_dns_record_set" "ns_child_same_project" {
  managed_zone = google_dns_managed_zone.test.name
  name         = google_dns_managed_zone.ns_child_same_project.dns_name
  type         = "NS"
  ttl          = 300
  rrdatas      = google_dns_managed_zone.ns_child_same_project.name_servers
}

#==============================================================================
# CASE 9: NS delegation -> child zone that EXISTS in a SECOND project
#
# This is the shape of the reported ENG-8964 false positive: the parent zone
# lives in project A and the delegated child zone lives in project B. When zone
# ownership is looked up only in project A, the delegation is reported as
# dangling even though the zone exists and answers authoritatively.
#
# Opt-in: set TF_VAR_secondary_project_id to a second GCP project in which you
# can create Cloud DNS zones. When it is unset, count = 0, nothing here is
# provisioned, the `ns_child_other_record` output is "", and the case-9 subtest
# skips.
#==============================================================================
resource "google_dns_managed_zone" "ns_child_other_project" {
  provider = google.secondary
  count    = var.secondary_project_id == "" ? 0 : 1

  name        = "${local.prefix}-child-other"
  dns_name    = "ns-child-other.${google_dns_managed_zone.test.dns_name}"
  description = "Aurelian ENG-8964 case 9: delegated child zone in a second project"
  labels      = local.labels
}

# The NS record itself lives in the PARENT zone, so it uses the default provider.
resource "google_dns_record_set" "ns_child_other_project" {
  count = var.secondary_project_id == "" ? 0 : 1

  managed_zone = google_dns_managed_zone.test.name
  name         = google_dns_managed_zone.ns_child_other_project[0].dns_name
  type         = "NS"
  ttl          = 300
  rrdatas      = google_dns_managed_zone.ns_child_other_project[0].name_servers
}

#==============================================================================
# CASE 10: NS delegation where ONLY A DEEPER zone exists
#
# `internal.ns-deep.${zone}` is a real Cloud DNS zone, but `ns-deep.${zone}` --
# the name actually delegated -- has no zone in any project. A zone BELOW the
# delegated name is a different zone and is not evidence that the delegation
# resolves, so this delegation is genuinely dangling and must be reported.
# A suffix-direction error in the existence test matches the deeper zone and
# silently suppresses this finding.
#==============================================================================
resource "google_dns_managed_zone" "ns_deep_child" {
  name        = "${local.prefix}-deep"
  dns_name    = "internal.ns-deep.${google_dns_managed_zone.test.dns_name}"
  description = "Aurelian ENG-8964 case 10: zone BELOW the delegated name"
  labels      = local.labels
}

resource "google_dns_record_set" "ns_deep_only" {
  managed_zone = google_dns_managed_zone.test.name
  name         = "ns-deep.${google_dns_managed_zone.test.dns_name}"
  type         = "NS"
  ttl          = 300
  # Real Cloud DNS nameservers (borrowed from the deeper zone) so the record is
  # realistic and reaches the ns-cloud-*.googledomains.com branch of checkNS.
  # No zone is ever created for ns-deep.${zone} itself.
  rrdatas = google_dns_managed_zone.ns_deep_child.name_servers
}

#==============================================================================
# CASE 12: NS delegation -> child zone that EXISTS in the SAME project but
# sorts PAST the first page of dns.managedZones.list
#
# ############################################################################
# ## COST WARNING -- THIS CASE IS OPT-IN AND IS NOT CHEAP                   ##
# ##                                                                        ##
# ## Setting TF_VAR_filler_zone_count provisions that many extra Cloud DNS  ##
# ## managed zones, plus one more for the delegated target, in order to     ##
# ## push the target past the first page of dns.managedZones.list (default  ##
# ## page size 100).                                                        ##
# ##                                                                        ##
# ## Cloud DNS bills per managed zone per month ($0.20/zone/month for the   ##
# ## first 25, $0.10/zone/month thereafter), and Aurelian fixtures PERSIST  ##
# ## between runs unless AURELIAN_DESTROY_FIXTURES=1. At the minimum        ##
# ## accepted value of 101 this fixture holds ~105 zones, roughly           ##
# ## 25*0.20 + 80*0.10 = $13.00 per month, and the bill rises linearly from ##
# ## there (150 fillers -> ~154 zones -> about $17.90 per month).           ##
# ##                                                                        ##
# ## The default is 0: nothing below is provisioned, the case-12 subtest    ##
# ## skips, and the rest of the fixture carries no pagination cost at all.  ##
# ############################################################################
#
# The defect (ENG-8964 defect 2): a zone-ownership lookup that reads only the
# first page of dns.managedZones.list never sees the delegated zone, so it
# reports a delegation that resolves perfectly well as dangling.
#
# ---- Ordering assumption (read before changing filler_zone_count or names) --
# dns.managedZones.list does NOT contractually guarantee an ordering, so this
# case does not depend on one. It is built to put the target past page 1 under
# either ordering that is plausible in practice:
#   * lexicographic by managed-zone name -- the fillers are
#     "<prefix>-filler-NNN" and the target is "<prefix>-zz-paged", which sorts
#     after every other zone this fixture creates ("child-other", "child-same",
#     "deep", "filler-NNN", "zone");
#   * creation order -- the target `depends_on` every filler zone, so it is
#     created last.
# Other zones already in the project only ADD to the count, which pushes the
# target deeper, never shallower. The test asserts the real invariant (no risk
# is emitted for the delegated name), not a page index.
#
# The filler zones carry no delegation of their own: the parent zone holds no
# NS record set pointing at them, and a zone's own apex NS record set is not a
# delegation (case 11), so they produce no findings.
#==============================================================================
resource "google_dns_managed_zone" "filler" {
  count = var.filler_zone_count

  name        = format("%s-filler-%03d", local.prefix, count.index)
  dns_name    = format("filler-%03d.%s", count.index, google_dns_managed_zone.test.dns_name)
  description = "Aurelian ENG-8964 case 12: pagination filler zone"
  labels      = local.labels
}

resource "google_dns_managed_zone" "ns_paged_child" {
  count = var.filler_zone_count > 0 ? 1 : 0

  # Created after every filler so a creation-ordered listing puts it last.
  depends_on = [google_dns_managed_zone.filler]

  name        = "${local.prefix}-zz-paged"
  dns_name    = "zz-paged.${google_dns_managed_zone.test.dns_name}"
  description = "Aurelian ENG-8964 case 12: delegated child zone past list page 1"
  labels      = local.labels
}

# The NS record itself lives in the PARENT zone.
resource "google_dns_record_set" "ns_paged_child" {
  count = var.filler_zone_count > 0 ? 1 : 0

  managed_zone = google_dns_managed_zone.test.name
  name         = google_dns_managed_zone.ns_paged_child[0].dns_name
  type         = "NS"
  ttl          = 300
  rrdatas      = google_dns_managed_zone.ns_paged_child[0].name_servers
}
