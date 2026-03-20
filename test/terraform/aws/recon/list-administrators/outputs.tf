output "prefix" {
  value = local.prefix
}

output "admin_user_name" {
  value = aws_iam_user.admin.name
}

output "admin_role_name" {
  value = aws_iam_role.admin.name
}

output "admin_group_name" {
  value = aws_iam_group.admin.name
}

output "admin_group_member_user_name" {
  value = aws_iam_user.admin_group_member.name
}

output "non_admin_user_name" {
  value = aws_iam_user.non_admin.name
}

output "non_admin_role_name" {
  value = aws_iam_role.non_admin.name
}

output "non_admin_group_name" {
  value = aws_iam_group.non_admin.name
}
