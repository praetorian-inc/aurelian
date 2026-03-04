output "prefix" {
  value = local.prefix
}

output "instance_id" {
  value = aws_instance.with_secret.id
}

output "function_name" {
  value = aws_lambda_function.with_secret.function_name
}

output "function_arn" {
  value = aws_lambda_function.with_secret.arn
}

output "stack_name" {
  value = aws_cloudformation_stack.with_secret.name
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.with_secret.name
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.with_secret.arn
}

output "ssm_document_name" {
  value = aws_ssm_document.with_secret.name
}

output "state_machine_arn" {
  value = aws_sfn_state_machine.with_secret.arn
}
