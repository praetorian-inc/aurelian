output "public_bucket_name" {
  value = aws_s3_bucket.public.id
}

output "private_bucket_name" {
  value = aws_s3_bucket.private.id
}

output "public_topic_arn" {
  value = aws_sns_topic.public.arn
}

output "public_queue_name" {
  value = aws_sqs_queue.public.name
}

output "public_function_name" {
  value = aws_lambda_function.public.function_name
}

output "public_function_arn" {
  value = aws_lambda_function.public.arn
}

output "lambda_policy_and_url_name" {
  value = aws_lambda_function.public_policy_and_url.function_name
}

output "lambda_policy_only_name" {
  value = aws_lambda_function.public_policy_only.function_name
}

output "lambda_private_name" {
  value = aws_lambda_function.private.function_name
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

output "public_ami_id" {
  value = aws_ami_copy.public.id
}

output "public_amplify_app_id" {
  value = aws_amplify_app.public.id
}

output "public_amplify_default_domain" {
  value = aws_amplify_app.public.default_domain
}

output "public_opensearch_domain" {
  value = aws_opensearch_domain.public.domain_name
}

output "prefix" {
  value = local.prefix
}

# --- Application ingress layer (feat/public-resources-ingress) ---

output "public_alb_arn" {
  value = aws_lb.public.arn
}

output "internal_alb_arn" {
  value = aws_lb.internal.arn
}

output "public_apprunner_arn" {
  value = aws_apprunner_service.public.arn
}

output "public_cloudfront_id" {
  value = aws_cloudfront_distribution.public.id
}

output "public_ga_arn" {
  value = aws_globalaccelerator_accelerator.public.arn
}

output "public_transfer_id" {
  value = aws_transfer_server.public.id
}

output "apikey_appsync_id" {
  value = aws_appsync_graphql_api.apikey.id
}

output "iam_appsync_id" {
  value = aws_appsync_graphql_api.iam.id
}

output "unauth_restapi_id" {
  value = aws_api_gateway_rest_api.public.id
}

output "unauth_httpapi_id" {
  value = aws_apigatewayv2_api.public.id
}

output "no_fgac_domain" {
  value = var.deploy_expensive ? aws_opensearch_domain.no_fgac[0].domain_name : ""
}

output "public_eks_arn" {
  value = var.deploy_expensive ? aws_eks_cluster.public[0].arn : ""
}

output "public_beanstalk_env" {
  value = var.deploy_expensive ? aws_elastic_beanstalk_environment.public[0].id : ""
}
