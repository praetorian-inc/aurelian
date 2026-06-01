output "instance_ids" {
  value = aws_instance.test[*].id
}

output "bucket_names" {
  value = aws_s3_bucket.test[*].id
}

output "function_arns" {
  value = aws_lambda_function.test[*].arn
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

output "restricted_role_arn" {
  value = aws_iam_role.restricted.arn
}

output "partial_ec2_role_arn" {
  value = aws_iam_role.partial_ec2.arn
}

output "region_restricted_role_arn" {
  value = aws_iam_role.region_restricted.arn
}
