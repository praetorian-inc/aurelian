output "user_name" {
  value = aws_iam_user.test.name
}

output "user_arn" {
  value = aws_iam_user.test.arn
}

output "role_name" {
  value = aws_iam_role.test.name
}

output "role_arn" {
  value = aws_iam_role.test.arn
}

output "group_name" {
  value = aws_iam_group.test.name
}

output "group_arn" {
  value = aws_iam_group.test.arn
}

output "policy_name" {
  value = aws_iam_policy.test.name
}

output "policy_arn" {
  value = aws_iam_policy.test.arn
}

output "prefix" {
  value = local.prefix
}
