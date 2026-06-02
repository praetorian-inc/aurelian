output "prefix" {
  value = local.prefix
}

output "admin_target_arn" {
  value = aws_iam_role.admin_target.arn
}

# Individual attacker ARN outputs — one per lab (fixture.Output() requires top-level strings)
output "lab_iam_001_arn"       { value = aws_iam_user.iam_001.arn }
output "lab_iam_002_arn"       { value = aws_iam_user.iam_002.arn }
output "lab_iam_004_arn"       { value = aws_iam_user.iam_004.arn }
output "lab_iam_006_arn"       { value = aws_iam_user.iam_006.arn }
output "lab_iam_012_arn"       { value = aws_iam_user.iam_012.arn }
output "lab_lambda_001_arn"    { value = aws_iam_user.lambda_001.arn }
output "lab_lambda_003_arn"    { value = aws_iam_user.lambda_003.arn }
output "lab_lambda_003fp_arn"  { value = aws_iam_user.lambda_fp_no_invoke.arn }
output "lab_glue_002_arn"      { value = aws_iam_user.glue_002.arn }
output "lab_glue_003_arn"      { value = aws_iam_user.glue_003.arn }
output "lab_ec2_001_arn"       { value = aws_iam_user.ec2_001.arn }
output "lab_ec2_003_arn"       { value = aws_iam_user.ec2_003.arn }
output "lab_ec2_004_arn"       { value = aws_iam_user.ec2_004.arn }

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

# FP user ARNs
output "lab_fp_passrole_only_arn"              { value = aws_iam_user.fp_passrole_only.arn }
output "lab_fp_lambda_createfunction_only_arn" { value = aws_iam_user.fp_lambda_createfunction_only.arn }
output "lab_fp_lambda_invoke_only_arn"         { value = aws_iam_user.fp_lambda_invoke_only.arn }
output "lab_fp_ec2_runinstances_only_arn"      { value = aws_iam_user.fp_ec2_runinstances_only.arn }
output "lab_fp_cfn_createstack_only_arn"       { value = aws_iam_user.fp_cfn_createstack_only.arn }
output "lab_fp_glue_createjob_only_arn"        { value = aws_iam_user.fp_glue_createjob_only.arn }
output "lab_fp_glue_passrole_createjob_arn"    { value = aws_iam_user.fp_glue_passrole_createjob_nostartjobrun.arn }
output "lab_fp_sfn_no_startexecution_arn"      { value = aws_iam_user.fp_sfn_no_startexecution.arn }
output "lab_fp_ecs_createservice_only_arn"     { value = aws_iam_user.fp_ecs_createservice_only.arn }
output "lab_fp_emrs_no_startjobrun_arn"        { value = aws_iam_user.fp_emr_serverless_no_startjobrun.arn }
output "lab_fp_ssm_createdoc_only_arn"         { value = aws_iam_user.fp_ssm_createdoc_only.arn }
