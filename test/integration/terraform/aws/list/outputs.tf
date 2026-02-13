output "instance_ids" {
  value = aws_instance.test[*].id
}

output "bucket_names" {
  value = aws_s3_bucket.test[*].id
}

output "function_arns" {
  value = aws_lambda_function.test[*].arn
}

output "prefix" {
  value = local.prefix
}
