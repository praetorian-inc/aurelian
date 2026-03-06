output "project_id" {
  value = data.google_project.current.project_id
}

output "public_bucket_name" {
  value = google_storage_bucket.public.name
}

output "private_bucket_name" {
  value = google_storage_bucket.private.name
}

output "instance_name" {
  value = google_compute_instance.test.name
}

output "instance_zone" {
  value = google_compute_instance.test.zone
}

output "sql_instance_name" {
  value = google_sql_database_instance.test.name
}

output "dns_zone_name" {
  value = google_dns_managed_zone.test.name
}

output "function_name" {
  value = google_cloudfunctions_function.public.name
}

output "cloud_run_public_name" {
  value = google_cloud_run_v2_service.public.name
}

output "cloud_run_private_name" {
  value = google_cloud_run_v2_service.private.name
}

output "global_address_name" {
  value = google_compute_global_address.test.name
}

output "regional_address_name" {
  value = google_compute_address.test.name
}

output "regional_forwarding_rule_name" {
  value = google_compute_forwarding_rule.test.name
}

output "private_instance_name" {
  value = google_compute_instance.private.name
}

output "private_dns_zone_name" {
  value = google_dns_managed_zone.private.name
}

output "prefix" {
  value = local.prefix
}
