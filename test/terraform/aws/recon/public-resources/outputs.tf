output "public_bucket_name" {
  value = aws_s3_bucket.public.id
}

output "private_bucket_name" {
  value = aws_s3_bucket.private.id
}

output "public_topic_arn" {
  value = aws_sns_topic.public.arn
}

output "public_queue_url" {
  value = aws_sqs_queue.public.id
}

output "public_function_name" {
  value = aws_lambda_function.public.function_name
}

output "public_function_arn" {
  value = aws_lambda_function.public.arn
}

output "public_instance_id" {
  value = aws_instance.public.id
}

output "public_efs_id" {
  value = aws_efs_file_system.public.id
}

output "public_cognito_pool_id" {
  value = aws_cognito_user_pool.public.id
}

output "public_rds_identifier" {
  value = aws_db_instance.public.identifier
}

output "public_opensearch_domain" {
  value = aws_opensearch_domain.public.domain_name
}

output "prefix" {
  value = local.prefix
}
