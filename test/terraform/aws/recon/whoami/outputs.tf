output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "arn" {
  value = data.aws_caller_identity.current.arn
}

output "user_id" {
  value = data.aws_caller_identity.current.user_id
}

output "region" {
  value = var.region
}
