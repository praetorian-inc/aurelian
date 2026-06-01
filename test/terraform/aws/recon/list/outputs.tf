output "instance_ids" {
  value = concat(aws_instance.test[*].id, aws_instance.test_secondary[*].id, aws_instance.test_tertiary[*].id)
}

# Per-region instance IDs for mosaic deny assertions.
output "instance_ids_primary" {
  value = aws_instance.test[*].id
}
output "instance_ids_secondary" {
  value = aws_instance.test_secondary[*].id
}
output "instance_ids_tertiary" {
  value = aws_instance.test_tertiary[*].id
}

output "bucket_names" {
  value = concat(aws_s3_bucket.test[*].id, aws_s3_bucket.test_secondary[*].id, aws_s3_bucket.test_tertiary[*].id)
}

output "function_arns" {
  value = concat(aws_lambda_function.test[*].arn, aws_lambda_function.test_secondary[*].arn, aws_lambda_function.test_tertiary[*].arn)
}

# Per-region function ARNs for mosaic deny assertions.
# us-east-2 (primary): Lambda DENIED by region_restricted role
# us-east-1 (secondary): Lambda allowed
# us-west-2 (tertiary): Lambda allowed
output "function_arns_primary" {
  value = aws_lambda_function.test[*].arn
}
output "function_arns_secondary" {
  value = aws_lambda_function.test_secondary[*].arn
}
output "function_arns_tertiary" {
  value = aws_lambda_function.test_tertiary[*].arn
}

output "prefix" {
  value = local.prefix
}

output "iam_role_arns" {
  value = aws_iam_role.test[*].arn
}

output "iam_role_names" {
  value = aws_iam_role.test[*].name
}

# Keep singular outputs for backward compat with existing tests.
output "iam_role_arn" {
  value = aws_iam_role.test[0].arn
}

output "iam_role_name" {
  value = aws_iam_role.test[0].name
}

output "iam_policy_arns" {
  value = aws_iam_policy.test[*].arn
}

output "iam_policy_names" {
  value = aws_iam_policy.test[*].name
}

output "iam_policy_arn" {
  value = aws_iam_policy.test[0].arn
}

output "iam_policy_name" {
  value = aws_iam_policy.test[0].name
}

output "iam_user_arns" {
  value = aws_iam_user.test[*].arn
}

output "iam_user_names" {
  value = aws_iam_user.test[*].name
}

output "iam_user_arn" {
  value = aws_iam_user.test[0].arn
}

output "iam_user_name" {
  value = aws_iam_user.test[0].name
}

output "amplify_app_id" {
  value = aws_amplify_app.test.id
}

output "amplify_app_name" {
  value = aws_amplify_app.test.name
}

# All regions where fixture resources are deployed. Tests should scan
# these regions to find all fixture resources.
output "test_regions" {
  value = distinct([var.region, var.secondary_region, var.tertiary_region])
}

# Region where the primary provider deploys (EC2, S3, Lambda primary resources).
output "primary_region" {
  value = var.region
}

output "secondary_region" {
  value = var.secondary_region
}

output "tertiary_region" {
  value = var.tertiary_region
}

# Amplify app is deployed in the primary region.
output "amplify_app_region" {
  value = var.region
}

# Mosaic role deny regions — tests should read these instead of hardcoding.
output "mosaic_deny_amplify_region" {
  value = var.secondary_region
}

output "mosaic_deny_lambda_region" {
  value = var.region
}

output "restricted_role_arn" {
  value = aws_iam_role.restricted.arn
}

output "partial_ec2_role_arn" {
  value = aws_iam_role.partial_ec2.arn
}

output "region_restricted_role_arn" {
  value = aws_iam_role.region_restricted.arn
}
