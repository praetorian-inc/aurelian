output "prefix" {
  value = local.prefix
}

output "qualifier" {
  value = local.qualifier
}

output "account_id" {
  value = local.account
}

output "region" {
  value = local.region
}

output "ssm_parameter_name" {
  value = aws_ssm_parameter.cdk_version.name
}

output "bucket_name" {
  value = aws_s3_bucket.cdk_staging.bucket
}

output "file_publishing_role_name" {
  value = aws_iam_role.file_publishing.name
}

output "qualifier_no_bucket" {
  value = local.qualifier_no_bucket
}

output "qualifier_no_ssm" {
  value = local.qualifier_no_ssm
}
