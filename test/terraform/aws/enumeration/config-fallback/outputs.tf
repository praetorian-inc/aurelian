output "target_bucket_name" {
  value = aws_s3_bucket.target.bucket
}

output "region" {
  value = var.region
}
