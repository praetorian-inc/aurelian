output "flagged_instance_ids" {
  value = [aws_instance.imdsv1_allowed.id]
}

output "safe_instance_ids" {
  value = [aws_instance.imdsv2_enforced.id, aws_instance.imds_disabled.id]
}

output "all_instance_ids" {
  value = [
    aws_instance.imdsv1_allowed.id,
    aws_instance.imdsv2_enforced.id,
    aws_instance.imds_disabled.id,
  ]
}

output "prefix" {
  value = local.prefix
}
