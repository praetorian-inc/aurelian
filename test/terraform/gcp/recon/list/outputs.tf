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

output "prefix" {
  value = local.prefix
}
