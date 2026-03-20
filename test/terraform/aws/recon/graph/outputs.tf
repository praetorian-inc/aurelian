output "prefix" {
  value = local.prefix
}

# IAM identifiers
output "user_names" {
  value = aws_iam_user.test[*].name
}

output "user_arns" {
  value = aws_iam_user.test[*].arn
}

output "group_name" {
  value = aws_iam_group.test.name
}

output "group_arn" {
  value = aws_iam_group.test.arn
}

output "lambda_role_name" {
  value = aws_iam_role.lambda.name
}

output "lambda_role_arn" {
  value = aws_iam_role.lambda.arn
}

output "assumable_role_name" {
  value = aws_iam_role.assumable.name
}

output "assumable_role_arn" {
  value = aws_iam_role.assumable.arn
}

output "custom_policy_arn" {
  value = aws_iam_policy.custom.arn
}

# Resource identifiers
output "s3_bucket_name" {
  value = aws_s3_bucket.test.id
}

output "s3_bucket_arn" {
  value = aws_s3_bucket.test.arn
}

output "sqs_queue_url" {
  value = aws_sqs_queue.test.url
}

output "sqs_queue_arn" {
  value = aws_sqs_queue.test.arn
}

output "sns_topic_arn" {
  value = aws_sns_topic.test.arn
}

output "lambda_function_arn" {
  value = aws_lambda_function.test.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.test.function_name
}

# Consolidated list of all fixture ARNs for test filtering
output "all_arns" {
  value = concat(
    aws_iam_user.test[*].arn,
    [aws_iam_group.test.arn],
    [aws_iam_role.lambda.arn],
    [aws_iam_role.assumable.arn],
    [aws_iam_policy.custom.arn],
    [aws_s3_bucket.test.arn],
    [aws_sqs_queue.test.arn],
    [aws_sns_topic.test.arn],
    [aws_lambda_function.test.arn],
  )
}

# Counts of each resource type created by this fixture
output "resource_counts" {
  value = {
    users              = length(aws_iam_user.test)
    groups             = 1
    roles              = 2 # lambda + assumable
    managed_policies   = 1 # custom
    s3_buckets         = 1
    sqs_queues         = 1
    sns_topics         = 1
    lambda_functions   = 1
    lambda_permissions = 2 # SNS + API Gateway
  }
}
