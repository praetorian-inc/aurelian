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
    aws_ecs_cluster.privesc.arn,
    aws_ecs_task_definition.privesc.arn,
    aws_ecs_service.privesc.id,
    aws_sfn_state_machine.privesc.arn,
    aws_glue_job.privesc.arn,
    aws_batch_job_queue.privesc.arn,
    aws_batch_job_definition.privesc.arn,
    aws_cognito_identity_pool.privesc.arn,
    aws_sagemaker_notebook_instance_lifecycle_configuration.privesc.arn,
    aws_imagebuilder_infrastructure_configuration.privesc.arn,
  ]
}

output "user_arns" {
  value = [
    aws_iam_user.iam_privesc.arn,
    aws_iam_user.new_services.arn,
    aws_iam_user.extended_services.arn,
  ]
}

output "ecs_cluster_arn" {
  value = aws_ecs_cluster.privesc.arn
}

output "ecs_service_id" {
  value = aws_ecs_service.privesc.id
}

output "sfn_state_machine_arn" {
  value = aws_sfn_state_machine.privesc.arn
}

output "glue_job_arn" {
  value = aws_glue_job.privesc.arn
}

output "batch_job_definition_arn" {
  value = aws_batch_job_definition.privesc.arn
}

output "batch_job_queue_arn" {
  value = aws_batch_job_queue.privesc.arn
}

output "cognito_identity_pool_arn" {
  value = aws_cognito_identity_pool.privesc.arn
}

output "scheduler_schedule_arn" {
  value = aws_scheduler_schedule.privesc.arn
}
