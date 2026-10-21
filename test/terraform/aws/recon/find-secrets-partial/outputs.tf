output "prefix" {
  value = local.prefix
}

output "scan_role_arn" {
  value = aws_iam_role.scan.arn
}

output "readable_function_arn" {
  value = aws_lambda_function.readable.arn
}

output "locked_function_arn" {
  value = aws_lambda_function.locked.arn
}

output "readable_stack_arn" {
  value = aws_cloudformation_stack.readable.id
}

output "locked_stack_arn" {
  value = aws_cloudformation_stack.locked.id
}
