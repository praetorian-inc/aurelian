output "random_suffix" {
  value       = local.suffix
  description = "Random suffix used for all resources"
}

output "region" {
  value       = var.region
  description = "AWS region where resources are deployed"
}
