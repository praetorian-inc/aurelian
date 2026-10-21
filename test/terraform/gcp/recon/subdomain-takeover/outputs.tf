output "project_id" {
  value = data.google_project.current.project_id
}

output "prefix" {
  value = local.prefix
}

output "zone_name" {
  value = google_dns_managed_zone.test.name
}

output "dns_name" {
  value = trimsuffix(google_dns_managed_zone.test.dns_name, ".")
}

# Dangling CNAME outputs
output "storage_cname_record" {
  value = trimsuffix(google_dns_record_set.storage_dangling.name, ".")
}

output "storage_cname_target" {
  value = trimsuffix(google_dns_record_set.storage_dangling.rrdatas[0], ".")
}

output "run_cname_record" {
  value = trimsuffix(google_dns_record_set.run_dangling.name, ".")
}

output "run_cname_target" {
  value = trimsuffix(google_dns_record_set.run_dangling.rrdatas[0], ".")
}

output "appengine_cname_record" {
  value = trimsuffix(google_dns_record_set.appengine_dangling.name, ".")
}

output "appengine_cname_target" {
  value = trimsuffix(google_dns_record_set.appengine_dangling.rrdatas[0], ".")
}

# Orphaned IP outputs
output "orphaned_ip_record" {
  value = trimsuffix(google_dns_record_set.ip_orphaned.name, ".")
}

output "orphaned_ip" {
  value = google_dns_record_set.ip_orphaned.rrdatas[0]
}

# NS delegation outputs
output "ns_record" {
  value = trimsuffix(google_dns_record_set.ns_dangling.name, ".")
}

# Safe record outputs (for negative testing)
output "safe_cname_record" {
  value = trimsuffix(google_dns_record_set.safe_cname.name, ".")
}

output "safe_a_record" {
  value = trimsuffix(google_dns_record_set.safe_a.name, ".")
}

#==============================================================================
# ENG-8964 NS zone-ownership cases
#==============================================================================

# Case 8: delegated child zone exists in the SAME project.
output "ns_child_same_record" {
  value = trimsuffix(google_dns_record_set.ns_child_same_project.name, ".")
}

output "ns_child_same_zone_name" {
  value = google_dns_managed_zone.ns_child_same_project.name
}

# Case 9: delegated child zone exists in a SECOND project.
# `secondary_project_id` is always present (empty when the case is disabled) so
# the test can detect the disabled state without a missing-output fatal.
output "secondary_project_id" {
  value = var.secondary_project_id
}

# A splat + join is used rather than `count == 0 ? "" : resource[0].name`:
# Terraform does not reliably short-circuit a conditional, so indexing a
# count = 0 resource in the unused branch can still fail with "Invalid index".
# With count = 0 the splat is [] and join yields "", which is the signal the
# case-9 subtest skips on.
output "ns_child_other_record" {
  value = trimsuffix(join("", google_dns_record_set.ns_child_other_project[*].name), ".")
}

output "ns_child_other_zone_name" {
  value = join("", google_dns_managed_zone.ns_child_other_project[*].name)
}

# Case 10: only a DEEPER zone exists; the delegated name itself has no zone.
output "ns_deep_record" {
  value = trimsuffix(google_dns_record_set.ns_deep_only.name, ".")
}

output "ns_deep_existing_zone_dns_name" {
  value = trimsuffix(google_dns_managed_zone.ns_deep_child.dns_name, ".")
}

# Case 12: delegated child zone exists in the SAME project, but past the first
# page of dns.managedZones.list.
#
# Always present (and string-typed, because the fixture helper unmarshals every
# output as a string) so the test can detect the disabled state without a
# missing-output fatal.
output "filler_zone_count" {
  value = tostring(var.filler_zone_count)
}

# Floor on the managed zones this fixture puts in the PRIMARY project: the
# parent zone, the case-8 same-project child, the case-10 deeper zone, the
# fillers, and the case-12 paged target. The project may hold more.
output "managed_zone_count" {
  value = tostring(3 + var.filler_zone_count + (var.filler_zone_count > 0 ? 1 : 0))
}

# Same empty-safe splat + join idiom as case 9: with count = 0 the splat is []
# and join yields "", which is the signal the case-12 subtest skips on. Do not
# index a possibly-zero-count resource here.
output "paged_ns_record" {
  value = trimsuffix(join("", google_dns_record_set.ns_paged_child[*].name), ".")
}

output "paged_target_zone_name" {
  value = join("", google_dns_managed_zone.ns_paged_child[*].name)
}
