output "healthy_distribution_id" {
  value = aws_cloudfront_distribution.healthy.id
}

output "vulnerable_distribution_id" {
  value = aws_cloudfront_distribution.vulnerable.id
}

output "healthy_bucket_name" {
  value = aws_s3_bucket.healthy.id
}

output "vulnerable_bucket_name" {
  value = aws_s3_bucket.vulnerable.id
}

output "prefix" {
  value = local.prefix
}
