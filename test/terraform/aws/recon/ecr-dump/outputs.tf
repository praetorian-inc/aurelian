output "prefix" {
  value = local.prefix
}

output "secret_repo_name" {
  value = aws_ecr_repository.with_secret.name
}

output "secret_repo_arn" {
  value = aws_ecr_repository.with_secret.arn
}

output "secret_repo_url" {
  value = aws_ecr_repository.with_secret.repository_url
}

output "empty_repo_name" {
  value = aws_ecr_repository.empty.name
}

output "empty_repo_arn" {
  value = aws_ecr_repository.empty.arn
}

output "region" {
  value = var.region
}
