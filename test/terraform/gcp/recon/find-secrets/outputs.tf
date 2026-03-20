output "project_id" {
  value = data.google_project.current.project_id
}

output "instance_name" {
  value = google_compute_instance.with_secret.name
}

output "function_name" {
  value = google_cloudfunctions_function.with_secret.name
}

output "cloud_run_service_name" {
  value = google_cloud_run_v2_service.with_secret.name
}

output "prefix" {
  value = local.prefix
}

output "bucket_name" {
  value = google_storage_bucket.with_secret.name
}
