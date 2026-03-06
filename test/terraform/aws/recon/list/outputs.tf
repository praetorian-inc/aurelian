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

output "iam_role_arn" {
  value = aws_iam_role.test.arn
}

output "iam_role_name" {
  value = aws_iam_role.test.name
}

output "iam_policy_arn" {
  value = aws_iam_policy.test.arn
}

output "iam_policy_name" {
  value = aws_iam_policy.test.name
}

output "iam_user_arn" {
  value = aws_iam_user.test.arn
}

output "iam_user_name" {
  value = aws_iam_user.test.name
}
