terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  backend "s3" {
    # All configured via -backend-config at init time
  }
}

provider "aws" {
  region = var.region
}

resource "random_id" "run" {
  byte_length = 4
}

data "aws_caller_identity" "current" {}

locals {
  prefix     = "aur-pf-${random_id.run.hex}"
  account_id = data.aws_caller_identity.current.account_id
  root_arn   = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
  tags       = { Purpose = "aurelian-pathfinding-e2e" }

  admin_policy = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# Phase-3 privesc-pathfinding fixture (foundation + common-compute tier).
#
# Structure (vs the old flat fixture):
#   - SHARED TARGETS: an admin role trusted by :root (assume reachability), per-service
#     admin roles whose trust policy names the consuming service (PassRole trust guard),
#     a privileged admin USER (principal-access target), an admin GROUP (self-escalation
#     target), an instance profile, plus DECOY roles for the trust-mismatch and
#     target-not-privileged FP categories.
#   - REAL COMPUTE (default tier): a Lambda function and an EC2 instance (+instance
#     profile) both running the admin role, so resource_to_role builds a real
#     (Resource)-[:HAS_ROLE]->(adminRole) edge on CloudControl-shaped data.
#   - ATTACKER USERS: one TP attacker per technique correctly satisfying its guard, plus
#     FP attackers per the 4-category taxonomy (missing-permission, trust-policy-mismatch,
#     no-usable-resource, target-not-privileged).
#
# Each user holds EXACTLY the permissions for its scenario, mirroring pathfinding.cloud
# labs, so per-method TP and FP can be asserted independently. Outputs map each principal
# to its expected verdict + target (see outputs.tf).
# =============================================================================

# -----------------------------------------------------------------------------
# Shared targets
# -----------------------------------------------------------------------------

# Admin role trusted by the account root → extract_role_trust_relationships builds a
# CAN_ASSUME edge from every same-account principal holding sts:AssumeRole. The escalation
# target for the trust-backed direct-takeover methods (sts_assume_role, iam_put_role_policy,
# iam_attach_role_policy, passrole_modify_policy) and the privileged-target for
# iam_update_assume_role_policy / update_assume_role_passrole_service.
resource "aws_iam_role" "admin_target" {
  name               = "${local.prefix}-admin-target"
  assume_role_policy = data.aws_iam_policy_document.trust_root.json
  tags               = local.tags
}
resource "aws_iam_role_policy_attachment" "admin_target" {
  role       = aws_iam_role.admin_target.name
  policy_arn = local.admin_policy
}

# Per-service admin roles: trust ONLY the consuming service principal (the PassRole trust
# guard: '<svc>.amazonaws.com' IN trusted_services) AND carry AdministratorAccess (admin
# target tier → high). One role per distinct trusted-service the common-tier PassRole
# methods consume. The map value is the service principal in the role's trust policy.
locals {
  service_trust_principals = {
    ec2          = "ec2.amazonaws.com"
    lambda       = "lambda.amazonaws.com"
    cloudform    = "cloudformation.amazonaws.com"
    datapipeline = "datapipeline.amazonaws.com"
    glue         = "glue.amazonaws.com"
    sagemaker    = "sagemaker.amazonaws.com"
    apprunner    = "tasks.apprunner.amazonaws.com"
    codebuild    = "codebuild.amazonaws.com"
    ecstasks     = "ecs-tasks.amazonaws.com"
    states       = "states.amazonaws.com"
    scheduler    = "scheduler.amazonaws.com"
    amplify      = "amplify.amazonaws.com"
    bedrock      = "bedrock-agentcore.amazonaws.com"
    ssm          = "ssm.amazonaws.com"
  }
}

resource "aws_iam_role" "service_admin" {
  for_each = local.service_trust_principals
  name     = "${local.prefix}-svcadmin-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = each.value }
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "service_admin" {
  for_each   = local.service_trust_principals
  role       = aws_iam_role.service_admin[each.key].name
  policy_arn = local.admin_policy
}

# The ec2-trusting svcadmin role is the target of the new-passrole + EC2-family methods
# (iam_pass_role_ec2, ec2_request_spot_instances, ec2_replace_instance_profile,
# ec2_launch_template_version, autoscaling_launch_template). EC2 only consumes a role via
# an INSTANCE PROFILE, so every one of those frozen guards requires
# `victim.InstanceProfileList CONTAINS 'arn:aws:iam'`. Attaching an instance profile to the
# ec2 svcadmin role surfaces InstanceProfileList on its GAAD node so the guards pass.
# Only the ec2-trusting svcadmin role needs this (the lambda/glue/cfn/etc. PassRole targets
# are consumed without an instance profile and have no such guard).
resource "aws_iam_instance_profile" "svcadmin_ec2" {
  name = "${local.prefix}-svcadmin-ec2"
  role = aws_iam_role.service_admin["ec2"].name
}

# Cognito identity-pool roles are NOT assumed by a Service principal — they are assumed via
# web-identity federation, so cognito-identity.amazonaws.com is a FEDERATED principal with
# sts:AssumeRoleWithWebIdentity (AWS rejects it as a Service principal: MalformedPolicyDocument).
# Broken out of the generic service_admin for_each because that template emits a Service trust.
#
# KNOWN GAP (documented in privesc_pathfinding_test.go): the frozen GAAD transformer
# NodeFromGaadRole extracts ONLY Principal.Service into trusted_services, never a Federated
# principal, and the frozen cognito_set_identity_pool_roles guard requires
# 'cognito-identity.amazonaws.com' IN victim.trusted_services. So with the (correct) Federated
# trust the cognito TP cannot fire without changing a frozen query — its case is a skip-logged
# known-gap, not a TP. This role still applies cleanly and is admin so the fixture is sound.
resource "aws_iam_role" "cognito_admin" {
  name = "${local.prefix}-svcadmin-cognito"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "cognito-identity.amazonaws.com" }
      # AWS IAM rejects a cognito-identity.amazonaws.com Federated trust without a Condition
      # keyed on that provider (MalformedPolicyDocument). The :aud is a placeholder pool-id —
      # IAM validates the Condition's presence/key shape, not that the pool exists, and this
      # role is never actually assumed (it only needs to apply + be an admin GAAD node).
      Condition = {
        StringEquals = {
          "cognito-identity.amazonaws.com:aud" = "us-east-2:00000000-0000-0000-0000-000000000000"
        }
      }
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "cognito_admin" {
  role       = aws_iam_role.cognito_admin.name
  policy_arn = local.admin_policy
}

# The shared compute exec role is consumed by the real EC2 instance, the SSM HAS_ROLE
# methods, AND the real Lambda function, so its trust must name all three consuming
# services: ec2 (to be an instance-profile role), ssm (so set_ssm_enabled_roles marks it
# _ssm_enabled for the SSM HAS_ROLE methods) AND lambda (Lambda CreateFunction validates
# lambda.amazonaws.com trust at create time). No PassRole TP/FP case targets this role (the
# lambda-trusting PassRole target is the separate service_admin["lambda"] role), so the
# extra lambda trust does not flip any case.
resource "aws_iam_role" "compute_admin" {
  name = "${local.prefix}-compute-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = ["ec2.amazonaws.com", "ssm.amazonaws.com", "lambda.amazonaws.com"] }
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "compute_admin" {
  role       = aws_iam_role.compute_admin.name
  policy_arn = local.admin_policy
}
resource "aws_iam_instance_profile" "compute_admin" {
  name = "${local.prefix}-compute-admin"
  role = aws_iam_role.compute_admin.name
}

# A privileged USER target for principal-access methods (CreateAccessKey/LoginProfile).
resource "aws_iam_user" "priv_user" {
  name = "${local.prefix}-priv-user"
  tags = local.tags
}
resource "aws_iam_user_policy_attachment" "priv_user" {
  user       = aws_iam_user.priv_user.name
  policy_arn = local.admin_policy
}

# The privileged user carries a CONSOLE LOGIN PROFILE so the D1-tightened
# iam_update_login_profile guard fires on the real signal: the GAAD collector's
# iam:GetLoginProfile succeeds → HasLoginProfile=true (a *bool tri-state) → the guard
# coalesce(target.HasLoginProfile, true) = true holds. WITHOUT this profile,
# GetLoginProfile returns NoSuchEntity → HasLoginProfile=confirmed-false → the guard
# correctly SUPPRESSES iam_update_login_profile (a NoSuchEntity at UpdateLoginProfile
# time), which is the exact false-negative the D1 loopback fix introduced and which this
# resource closes for the TP. No PGP key is supplied, so the generated password lands in
# Terraform state (sensitive); the profile is never actually used — only collected.
resource "aws_iam_user_login_profile" "priv_user" {
  user                    = aws_iam_user.priv_user.name
  password_length         = 20
  password_reset_required = false
}

# A NON-privileged USER target for the target-not-privileged FP category.
resource "aws_iam_user" "nonpriv_user" {
  name = "${local.prefix}-nonpriv-user"
  tags = local.tags
}

# An admin GROUP target for iam_add_user_to_group (self-escalation by JOINing it). The
# AddUserToGroup attacker must NOT already be a member, so nothing is wired into this group.
resource "aws_iam_group" "admin_group" {
  name = "${local.prefix}-admin-group"
}
resource "aws_iam_group_policy_attachment" "admin_group" {
  group      = aws_iam_group.admin_group.name
  policy_arn = local.admin_policy
}

# A member GROUP for the iam_put_group_policy / iam_attach_group_policy self-escalation
# attackers: those guards require the attacker to ALREADY be a member (GroupName IN
# attacker.GroupList) so the privilege they grant the group accrues to themselves. The
# group need not be admin (the attacker makes it admin by writing the policy).
resource "aws_iam_group" "member_group" {
  name = "${local.prefix}-member-group"
}
resource "aws_iam_user_group_membership" "put_group_policy" {
  user   = aws_iam_user.attacker["iam_put_group_policy"].name
  groups = [aws_iam_group.member_group.name]
}
resource "aws_iam_user_group_membership" "attach_group_policy" {
  user   = aws_iam_user.attacker["iam_attach_group_policy"].name
  groups = [aws_iam_group.member_group.name]
}

# DECOY: a role whose trust names a DIFFERENT principal (the non-priv user), not :root and
# not the attacker → no CAN_ASSUME is built for an arbitrary attacker. Backs the AssumeRole
# trust-policy-mismatch FP. It is admin so the FP is purely about TRUST, not privilege.
resource "aws_iam_role" "trust_mismatch_target" {
  name = "${local.prefix}-trust-mismatch"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.nonpriv_user.arn }
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "trust_mismatch_target" {
  role       = aws_iam_role.trust_mismatch_target.name
  policy_arn = local.admin_policy
}

# DECOY: a role that trusts the WRONG service (sqs, never a PassRole compute consumer) but
# is admin → backs the PassRole trust-policy-mismatch FP (passed role doesn't trust the
# service the attacker is creating compute in).
resource "aws_iam_role" "wrong_service_target" {
  name = "${local.prefix}-wrong-service"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "sqs.amazonaws.com" }
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "wrong_service_target" {
  role       = aws_iam_role.wrong_service_target.name
  policy_arn = local.admin_policy
}

# DECOY: a role that trusts the lambda service correctly but is NON-privileged → backs the
# target-not-privileged FP for new-passrole methods (least-privilege exec role = lateral).
resource "aws_iam_role" "nonpriv_lambda_target" {
  name = "${local.prefix}-nonpriv-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = local.tags
}

data "aws_iam_policy_document" "trust_root" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }
}

# -----------------------------------------------------------------------------
# Real common-tier compute: exercises (Resource)-[:HAS_ROLE]->(adminRole) on real
# CloudControl-shaped data. Lambda + EC2 both run compute_admin (an admin role).
# -----------------------------------------------------------------------------

# Minimal inline-zip Lambda running the admin role.
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/.lambda.zip"
  source {
    content  = "def handler(event, context):\n    return {}\n"
    filename = "index.py"
  }
}
resource "aws_lambda_function" "compute" {
  function_name    = "${local.prefix}-compute"
  role             = aws_iam_role.compute_admin.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  tags             = local.tags
}

# A single t3.micro instance using the admin instance profile. Uses the default VPC's
# default subnet/SG so no networking is provisioned. Latest Amazon Linux 2023 AMI.
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}
resource "aws_instance" "compute" {
  ami                  = data.aws_ami.al2023.id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.compute_admin.name
  tags                 = merge(local.tags, { Name = "${local.prefix}-compute" })
}

# =============================================================================
# Attacker users. Each entry in local.attackers becomes one aws_iam_user +
# aws_iam_user_policy. `statements` is the inline policy statement list; group
# membership / managed-policy attachment for the self-escalation attackers that
# need AttachedManagedPolicies/GroupList are wired separately below.
# =============================================================================

locals {
  attackers = {
    # ---- IAM self-escalation (target = self) ----
    iam_create_policy_version      = [{ actions = ["iam:CreatePolicyVersion"], resources = ["*"] }]
    iam_set_default_policy_version = [{ actions = ["iam:SetDefaultPolicyVersion"], resources = ["*"] }]
    iam_put_user_policy            = [{ actions = ["iam:PutUserPolicy"], resources = ["*"] }]
    iam_attach_user_policy         = [{ actions = ["iam:AttachUserPolicy"], resources = ["*"] }]
    iam_put_group_policy           = [{ actions = ["iam:PutGroupPolicy"], resources = ["*"] }]
    iam_attach_group_policy        = [{ actions = ["iam:AttachGroupPolicy"], resources = ["*"] }]
    iam_add_user_to_group          = [{ actions = ["iam:AddUserToGroup"], resources = ["*"] }]
    ssm_createdoc_startauto        = [{ actions = ["ssm:CreateDocument", "ssm:StartAutomationExecution"], resources = ["*"] }]

    # ---- IAM principal-access (target = privileged user) ----
    iam_create_access_key    = [{ actions = ["iam:CreateAccessKey", "iam:DeleteAccessKey"], resources = ["*"] }]
    iam_create_login_profile = [{ actions = ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"], resources = ["*"] }]
    iam_update_login_profile = [{ actions = ["iam:UpdateLoginProfile"], resources = ["*"] }]

    # ---- IAM trust-backed direct takeover (target = :root-trusted admin role) ----
    iam_put_role_policy                 = [{ actions = ["iam:PutRolePolicy", "sts:AssumeRole"], resources = ["*"] }]
    iam_attach_role_policy              = [{ actions = ["iam:AttachRolePolicy", "sts:AssumeRole"], resources = ["*"] }]
    iam_update_assume_role_policy       = [{ actions = ["iam:UpdateAssumeRolePolicy"], resources = ["*"] }]
    sts_assume_role                     = [{ actions = ["sts:AssumeRole"], resources = ["*"] }]
    passrole_modify_policy              = [{ actions = ["iam:PassRole", "iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy"], resources = ["*"] }]
    update_assume_role_passrole_service = [{ actions = ["iam:UpdateAssumeRolePolicy", "iam:PassRole"], resources = ["*"] }]

    # ---- New-passrole + create compute (target = service-trusted admin role) ----
    iam_pass_role_ec2          = [{ actions = ["iam:PassRole", "ec2:RunInstances"], resources = ["*"] }]
    iam_pass_role_lambda       = [{ actions = ["iam:PassRole", "lambda:CreateFunction"], resources = ["*"] }]
    iam_pass_role_cloudform    = [{ actions = ["iam:PassRole", "cloudformation:CreateStack"], resources = ["*"] }]
    cloudform_create_stackset  = [{ actions = ["iam:PassRole", "cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"], resources = ["*"] }]
    iam_pass_role_datapipeline = [{ actions = ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"], resources = ["*"] }]
    iam_pass_role_glue         = [{ actions = ["iam:PassRole", "glue:CreateJob"], resources = ["*"] }]
    iam_pass_role_sagemaker    = [{ actions = ["iam:PassRole", "sagemaker:CreateNotebookInstance"], resources = ["*"] }]
    ec2_request_spot           = [{ actions = ["iam:PassRole", "ec2:RequestSpotInstances"], resources = ["*"] }]
    ec2_replace_profile        = [{ actions = ["iam:PassRole", "ec2:ReplaceIamInstanceProfileAssociation"], resources = ["*"] }]
    ec2_launch_template_ver    = [{ actions = ["iam:PassRole", "ec2:CreateLaunchTemplateVersion", "ec2:ModifyLaunchTemplate"], resources = ["*"] }]
    autoscaling_launch_tpl     = [{ actions = ["iam:PassRole", "ec2:CreateLaunchTemplate", "autoscaling:CreateAutoScalingGroup"], resources = ["*"] }]
    apprunner_create_service   = [{ actions = ["iam:PassRole", "apprunner:CreateService"], resources = ["*"] }]
    codebuild_create_project   = [{ actions = ["iam:PassRole", "codebuild:CreateProject"], resources = ["*"] }]
    codebuild_update_project   = [{ actions = ["iam:PassRole", "codebuild:UpdateProject"], resources = ["*"] }]
    cognito_set_pool_roles     = [{ actions = ["iam:PassRole", "cognito-identity:SetIdentityPoolRoles", "cognito-identity:GetId", "cognito-identity:GetCredentialsForIdentity"], resources = ["*"] }]
    ecs_create_service         = [{ actions = ["iam:PassRole", "ecs:CreateService"], resources = ["*"] }]
    ecs_passrole_runtask       = [{ actions = ["iam:PassRole", "ecs:RunTask"], resources = ["*"] }]
    ecs_start_task             = [{ actions = ["iam:PassRole", "ecs:StartTask"], resources = ["*"] }]
    glue_create_dev_endpoint   = [{ actions = ["iam:PassRole", "glue:CreateDevEndpoint"], resources = ["*"] }]
    glue_create_session        = [{ actions = ["iam:PassRole", "glue:CreateSession"], resources = ["*"] }]
    glue_createjob_trigger     = [{ actions = ["iam:PassRole", "glue:CreateJob", "glue:CreateTrigger"], resources = ["*"] }]
    glue_createjob_startjobrun = [{ actions = ["iam:PassRole", "glue:CreateJob", "glue:StartJobRun"], resources = ["*"] }]
    glue_session_runstatement  = [{ actions = ["iam:PassRole", "glue:CreateSession", "glue:RunStatement"], resources = ["*"] }]
    scheduler_create_schedule  = [{ actions = ["iam:PassRole", "scheduler:CreateSchedule"], resources = ["*"] }]
    ssm_start_automation       = [{ actions = ["iam:PassRole", "ssm:StartAutomationExecution"], resources = ["*"] }]
    stepfunctions_create       = [{ actions = ["iam:PassRole", "states:CreateStateMachine"], resources = ["*"] }]
    stepfunctions_create_start = [{ actions = ["iam:PassRole", "states:CreateStateMachine", "states:StartExecution"], resources = ["*"] }]
    lambda_passrole_addperm    = [{ actions = ["iam:PassRole", "lambda:CreateFunction", "lambda:AddPermission"], resources = ["*"] }]
    sagemaker_processing_job   = [{ actions = ["iam:PassRole", "sagemaker:CreateProcessingJob"], resources = ["*"] }]
    sagemaker_training_job     = [{ actions = ["iam:PassRole", "sagemaker:CreateTrainingJob"], resources = ["*"] }]
    bedrock_create_ci          = [{ actions = ["iam:PassRole", "bedrock-agentcore:CreateCodeInterpreter", "bedrock-agentcore:StartCodeInterpreterSession", "bedrock-agentcore:InvokeSession"], resources = ["*"] }]
    amplify_create_app         = [{ actions = ["iam:PassRole", "amplify:CreateApp", "amplify:CreateBranch", "amplify:StartJob"], resources = ["*"] }]
    batch_passrole             = [{ actions = ["iam:PassRole", "batch:RegisterJobDefinition", "batch:SubmitJob"], resources = ["*"] }]

    # ---- Existing-compute via HAS_ROLE (target = the resource's admin exec role) ----
    lambda_update_code         = [{ actions = ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"], resources = ["*"] }]
    lambda_updatecode_invoke   = [{ actions = ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"], resources = ["*"] }]
    lambda_add_permission      = [{ actions = ["lambda:UpdateFunctionCode", "lambda:AddPermission"], resources = ["*"] }]
    lambda_create_esm          = [{ actions = ["lambda:UpdateFunctionCode", "lambda:CreateEventSourceMapping"], resources = ["*"] }]
    ec2_modify_attribute       = [{ actions = ["ec2:ModifyInstanceAttribute", "ec2:StopInstances", "ec2:StartInstances"], resources = ["*"] }]
    ec2_instance_connect       = [{ actions = ["ec2-instance-connect:SendSSHPublicKey"], resources = ["*"] }]
    ec2_ssm_association        = [{ actions = ["ssm:CreateAssociation"], resources = ["*"] }]
    ssm_send_command           = [{ actions = ["ssm:SendCommand"], resources = ["*"] }]
    ssm_start_session          = [{ actions = ["ssm:StartSession"], resources = ["*"] }]
    cloudform_update_stack     = [{ actions = ["cloudformation:UpdateStack"], resources = ["*"] }]
    cloudform_update_stackset  = [{ actions = ["cloudformation:UpdateStackSet"], resources = ["*"] }]
    codebuild_start_build      = [{ actions = ["codebuild:StartBuild"], resources = ["*"] }]
    codedeploy_create_deploy   = [{ actions = ["codedeploy:CreateDeployment"], resources = ["*"] }]
    apprunner_update_service   = [{ actions = ["apprunner:UpdateService"], resources = ["*"] }]
    ecs_execute_command        = [{ actions = ["ecs:ExecuteCommand", "ecs:DescribeTasks"], resources = ["*"] }]
    stepfunctions_update       = [{ actions = ["states:UpdateStateMachine", "states:StartExecution"], resources = ["*"] }]
    glue_update_dev_endpoint   = [{ actions = ["glue:UpdateDevEndpoint"], resources = ["*"] }]
    glue_update_job            = [{ actions = ["glue:UpdateJob"], resources = ["*"] }]
    glue_updatejob_startjobrun = [{ actions = ["glue:UpdateJob", "glue:StartJobRun"], resources = ["*"] }]
    glue_updatejob_trigger     = [{ actions = ["glue:UpdateJob", "glue:CreateTrigger"], resources = ["*"] }]
    sagemaker_lifecycle        = [{ actions = ["sagemaker:UpdateNotebookInstanceLifecycleConfig"], resources = ["*"] }]
    sagemaker_presigned        = [{ actions = ["sagemaker:CreatePresignedNotebookInstanceUrl"], resources = ["*"] }]

    # ---- Service-wildcard fail-open (target = permission stub) ----
    batch_submit_job    = [{ actions = ["batch:SubmitJob"], resources = ["*"] }]
    bedrock_invoke      = [{ actions = ["bedrock-agentcore:InvokeSession"], resources = ["*"] }]
    cloudform_changeset = [{ actions = ["cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"], resources = ["*"] }]

    # ---- Intentional no-op ----
    iam_create_slr  = [{ actions = ["iam:CreateServiceLinkedRole"], resources = ["*"] }]
    codestar_create = [{ actions = ["codestar:CreateProject"], resources = ["*"] }]

    # =====================================================================
    # FALSE-POSITIVE attackers (4-category taxonomy)
    # =====================================================================

    # cat-1 missing-permission
    fp_passrole_only           = [{ actions = ["iam:PassRole"], resources = ["*"] }]
    fp_lambda_create_only      = [{ actions = ["lambda:CreateFunction"], resources = ["*"] }]
    fp_lambda_invoke_only      = [{ actions = ["lambda:InvokeFunction"], resources = ["*"] }]
    fp_lambda_no_trigger       = [{ actions = ["lambda:UpdateFunctionCode"], resources = ["*"] }]
    fp_ec2_run_only            = [{ actions = ["ec2:RunInstances"], resources = ["*"] }]
    fp_cfn_create_only         = [{ actions = ["cloudformation:CreateStack"], resources = ["*"] }]
    fp_glue_createjob_only     = [{ actions = ["glue:CreateJob"], resources = ["*"] }]
    fp_sfn_no_start            = [{ actions = ["iam:PassRole", "states:CreateStateMachine"], resources = ["*"] }]
    fp_ecs_create_only         = [{ actions = ["ecs:CreateService"], resources = ["*"] }]
    fp_ssm_createdoc_only      = [{ actions = ["ssm:CreateDocument"], resources = ["*"] }]
    fp_changeset_create_only   = [{ actions = ["cloudformation:CreateChangeSet"], resources = ["*"] }]
    fp_ecs_runtask_no_passrole = [{ actions = ["ecs:RunTask"], resources = ["*"] }]
    fp_sfn_updatesm_only       = [{ actions = ["states:UpdateStateMachine"], resources = ["*"] }]

    # cat-2 trust-policy-mismatch — PassRole is SCOPED to the wrong-service decoy role, so the
    # IAM_PASSROLE permission edge targets ONLY that role (the evaluator resource-scopes edges).
    # The wrong-service role does not trust lambda → iam_pass_role_lambda must NOT fire.
    # CreateFunction stays broad (the trigger MATCH is any-resource).
    fp_passrole_wrong_service = [
      { actions = ["iam:PassRole"], resources = [aws_iam_role.wrong_service_target.arn] },
      { actions = ["lambda:CreateFunction"], resources = ["*"] },
    ]

    # cat-4 target-not-privileged — PassRole SCOPED to a lambda-trusting but NON-privileged role,
    # so iam_pass_role_lambda's privileged-target guard fails. CreateAccessKey SCOPED to the
    # non-privileged user, so iam_create_access_key's privileged-target guard fails.
    fp_passrole_nonpriv_target = [
      { actions = ["iam:PassRole"], resources = [aws_iam_role.nonpriv_lambda_target.arn] },
      { actions = ["lambda:CreateFunction"], resources = ["*"] },
    ]
    fp_accesskey_nonpriv = [{ actions = ["iam:CreateAccessKey", "iam:DeleteAccessKey"], resources = [aws_iam_user.nonpriv_user.arn] }]
  }
}

resource "aws_iam_user" "attacker" {
  for_each = local.attackers
  name     = "${local.prefix}-${replace(each.key, "_", "-")}"
  tags     = merge(local.tags, { Lab = each.key })
}

resource "aws_iam_user_policy" "attacker" {
  for_each = local.attackers
  name     = "${local.prefix}-${replace(each.key, "_", "-")}"
  user     = aws_iam_user.attacker[each.key].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [for s in each.value : {
      Effect   = "Allow"
      Action   = s.actions
      Resource = s.resources
    }]
  })
}

# The customer-managed policy attached to the CreatePolicyVersion / SetDefaultPolicyVersion
# attackers (so set_admin sees nothing, but the self-loop guard's attached-to-attacker
# CONTAINS check passes). Grants only a harmless read.
resource "aws_iam_policy" "custom" {
  name = "${local.prefix}-custom"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:GetUser"], Resource = "*" }]
  })
}
resource "aws_iam_user_policy_attachment" "create_policy_version_custom" {
  user       = aws_iam_user.attacker["iam_create_policy_version"].name
  policy_arn = aws_iam_policy.custom.arn
}
resource "aws_iam_user_policy_attachment" "set_default_policy_version_custom" {
  user       = aws_iam_user.attacker["iam_set_default_policy_version"].name
  policy_arn = aws_iam_policy.custom.arn
}
