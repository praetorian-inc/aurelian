output "prefix" {
  value = local.prefix
}

output "admin_target_arn" {
  value = aws_iam_role.admin_target.arn
}

# Per-lab attacker ARNs — used by the table-driven E2E test to assert
# that each attacker produces exactly the expected CAN_PRIVESC edges.
output "attacker_arns" {
  value = {
    "iam-001"         = aws_iam_user.iam_001.arn
    "iam-002"         = aws_iam_user.iam_002.arn
    "iam-004"         = aws_iam_user.iam_004.arn
    "iam-006"         = aws_iam_user.iam_006.arn
    "iam-012"         = aws_iam_user.iam_012.arn
    "lambda-001"      = aws_iam_user.lambda_001.arn
    "lambda-003"      = aws_iam_user.lambda_003.arn
    "lambda-003-fp"   = aws_iam_user.lambda_fp_no_invoke.arn
    "glue-002"        = aws_iam_user.glue_002.arn
    "glue-003"        = aws_iam_user.glue_003.arn
    "ec2-001"         = aws_iam_user.ec2_001.arn
    "ec2-003"         = aws_iam_user.ec2_003.arn
    "ec2-004"         = aws_iam_user.ec2_004.arn
  }
}

output "all_arns" {
  value = [
    aws_iam_role.admin_target.arn,
    aws_iam_user.iam_001.arn,
    aws_iam_user.iam_002.arn,
    aws_iam_user.iam_004.arn,
    aws_iam_user.iam_006.arn,
    aws_iam_user.iam_012.arn,
    aws_iam_user.lambda_001.arn,
    aws_iam_user.lambda_003.arn,
    aws_iam_user.lambda_fp_no_invoke.arn,
    aws_iam_user.glue_002.arn,
    aws_iam_user.glue_003.arn,
    aws_iam_user.ec2_001.arn,
    aws_iam_user.ec2_003.arn,
    aws_iam_user.ec2_004.arn,
  ]
}
