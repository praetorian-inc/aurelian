output "prefix" {
  value = local.prefix
}

output "instance_id" {
  value = aws_instance.test.id
}

output "lambda_function_name" {
  value = aws_lambda_function.test.function_name
}

output "cloudformation_stack_name" {
  value = aws_cloudformation_stack.test.name
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.test.name
}

output "test_secret" {
  value = local.test_secret
}

output "region" {
  value = var.region
}
