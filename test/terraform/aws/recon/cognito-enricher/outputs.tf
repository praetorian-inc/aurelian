output "cognito_pool_id" {
  value = aws_cognito_user_pool.test.id
}

output "cognito_group_name" {
  value = aws_cognito_user_group.admins.name
}

output "cognito_group_role_arn" {
  value = aws_iam_role.group.arn
}

output "prefix" {
  value = local.prefix
}
