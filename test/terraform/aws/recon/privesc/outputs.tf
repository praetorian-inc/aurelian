output "prefix" {
  value = local.prefix
}

output "passable_role_arn" {
  value = aws_iam_role.passable.arn
}

output "iam_privesc_user_arn" {
  value = aws_iam_user.iam_privesc.arn
}

output "new_services_user_arn" {
  value = aws_iam_user.new_services.arn
}

output "extended_services_user_arn" {
  value = aws_iam_user.extended_services.arn
}

output "all_arns" {
  value = [
    aws_iam_role.passable.arn,
    aws_iam_user.iam_privesc.arn,
    aws_iam_user.new_services.arn,
    aws_iam_user.extended_services.arn,
  ]
}

output "user_arns" {
  value = [
    aws_iam_user.iam_privesc.arn,
    aws_iam_user.new_services.arn,
    aws_iam_user.extended_services.arn,
  ]
}
