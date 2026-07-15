output "external_share_arn" {
  value = aws_ram_resource_share.external.arn
}

output "external_share_name" {
  value = aws_ram_resource_share.external.name
}

output "org_only_share_arn" {
  value = aws_ram_resource_share.org_only.arn
}

output "external_principal_id" {
  value = var.external_account_id
}
