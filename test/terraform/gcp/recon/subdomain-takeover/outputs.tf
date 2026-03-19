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
