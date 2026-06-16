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
#
# ==================== BRANCH-COVERAGE TEST CASES ====================
# Each row exercises a distinct BRANCH of its method (other rows cover a different
# branch of the same method). Verdict is asserted by privesc_integration_test.go labCases.
#
# | Case key                     | Method                          | Tier   | Verdict | Backing resource          |
# |------------------------------|---------------------------------|--------|---------|---------------------------|
# | iam_pass_role_lambda_cond    | iam_pass_role_lambda            | common | FLAGGED | none (IAM-only, cond.)    |
# | ssm_managed_send_command     | ssm_send_command                | common | FLAGGED | ssm_managed role + EC2    |
# | ssm_managed_start_session    | ssm_start_session               | common | FLAGGED | ssm_managed role + EC2    |
# | lambda_update_code_real      | lambda_update_function_code     | common | FLAGGED | real aws_lambda_function  |
# | glue_passrole_updatejob      | glue_updatejob_startjobrun      | common | FLAGGED | none (IAM-only passrole)  |
# | ec2_launch_template_existing | ec2_launch_template_version     | common | FLAGGED | aws_launch_template       |
# | cognito_unauth_pool          | cognito_set_identity_pool_roles | common | FLAGGED | unauth identity pool      |
# | apprunner_update_concrete    | apprunner_update_service        | full   | FLAGGED | aws_apprunner_service     |
# | sagemaker_lifecycle_create   | sagemaker_lifecycle_config      | full   | FLAGGED | sagemaker notebook        |
# | fp_passrole_cond_only        | iam_pass_role_lambda            | common | NOT     | none                      |
# | fp_ssm_managed_no_send       | ssm_send_command                | common | NOT     | ssm_managed role + EC2    |
# | fp_cognito_authpool_no_getid | cognito_set_identity_pool_roles | common | NOT     | auth-only identity pool   |
# | fp_ec2_lt_passrole_only      | ec2_launch_template_version     | common | NOT     | aws_launch_template       |
#
# FP Rationale:
#   fp_passrole_cond_only:        conditional PassRole forms IAM_PASSROLE but no lambda:CreateFunction.
#   fp_ssm_managed_no_send:       HAS_ROLE + _ssm_enabled present, but no ssm:SendCommand/StartSession.
#   fp_cognito_authpool_no_getid: auth-only pool + no GetId/GetCredentials -> unauth relax is scoped out.
#   fp_ec2_lt_passrole_only:      PassRole(ec2) only, no CreateLaunchTemplateVersion/ModifyLaunchTemplate.
# =============================================================================

# -----------------------------------------------------------------------------
# Shared targets
# -----------------------------------------------------------------------------

# Admin role trusted by the account root → every same-account principal holding sts:AssumeRole
# gets a validated STS_ASSUMEROLE edge to it (the evaluator emits it from identity AND trust).
# The escalation target for the trust-backed direct-takeover methods (sts_assume_role, iam_put_role_policy,
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
# methods, the real Lambda function, AND (Phase-2a) the real backing service resources that
# back the existing-compute HAS_ROLE methods targeting tgtComputeRole — the CloudFormation
# stack/stackset, Step Functions state machine, Glue job, CodeBuild project, and ECS task
# definition all RUN AS this admin role so resource_service_role builds a real
# (Resource)-[:HAS_ROLE]->(compute_admin) edge. Its trust therefore names every consuming
# service: ec2 (instance-profile role), ssm (so set_ssm_enabled_roles marks it _ssm_enabled),
# lambda (Lambda CreateFunction validates lambda.amazonaws.com trust at create time),
# cloudformation (CFN service role), states (SFN CreateStateMachine validates trust),
# glue (Glue CreateJob validates trust), codebuild (CodeBuild CreateProject validates trust),
# ecs-tasks (ECS task role / execution role), and sagemaker (the full-tier real SageMaker
# notebook instance aws_sagemaker_notebook_instance.existing in full.tf, gated by
# var.enable_full, runs this role as its execution role and SageMaker validates the
# sagemaker.amazonaws.com trust at notebook-create time). No PassRole TP/FP case targets this
# role (the per-service PassRole targets are the separate service_admin[...] roles), so the
# extra service trusts do not flip any case.
resource "aws_iam_role" "compute_admin" {
  name = "${local.prefix}-compute-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = { Service = [
        "ec2.amazonaws.com",
        "ssm.amazonaws.com",
        "lambda.amazonaws.com",
        "cloudformation.amazonaws.com",
        "states.amazonaws.com",
        "glue.amazonaws.com",
        "codebuild.amazonaws.com",
        "ecs-tasks.amazonaws.com",
        "sagemaker.amazonaws.com",
      ] }
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

# A privileged USER with NO console login profile. The GAAD collector's iam:GetLoginProfile
# returns NoSuchEntity → HasLoginProfile=confirmed-false → the iam_update_login_profile guard
# coalesce(target.HasLoginProfile, true) = true is unmet → the method SUPPRESSES (UpdateLoginProfile
# would itself return NoSuchEntity). Backs fp_updateloginprofile_no_profile. Admin so the
# suppression is purely about the missing profile, not target privilege.
resource "aws_iam_user" "noprofile_user" {
  name = "${local.prefix}-noprofile-user"
  tags = local.tags
}
resource "aws_iam_user_policy_attachment" "noprofile_user" {
  user       = aws_iam_user.noprofile_user.name
  policy_arn = local.admin_policy
}

# A privileged USER that already holds TWO active access keys. The GAAD collector's
# iam:ListAccessKeys returns AccessKeyCount=2 → the iam_create_access_key guard
# (AccessKeyCount < 2) is unmet → the method SUPPRESSES (AWS caps a user at 2 active keys, so
# CreateAccessKey would return LimitExceeded). Backs fp_createaccesskey_two_keys. Admin so the
# suppression is purely about the key-count limit, not target privilege.
resource "aws_iam_user" "twokey_user" {
  name = "${local.prefix}-twokey-user"
  tags = local.tags
}
resource "aws_iam_user_policy_attachment" "twokey_user" {
  user       = aws_iam_user.twokey_user.name
  policy_arn = local.admin_policy
}
resource "aws_iam_access_key" "twokey_user" {
  count = 2
  user  = aws_iam_user.twokey_user.name
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

# fp_adduser_nonpriv_group is ALREADY a member of the privileged admin_group (so that group is
# excluded by the guard's "not already a member" clause), leaving only the NON-privileged
# member_group reachable — which the guard's "target group must be privileged" clause excludes.
# It is deliberately NOT a member of member_group, so removing the privileged-group guard would
# let it fire on member_group (proving the FP is sound, not vacuous).
resource "aws_iam_user_group_membership" "fp_adduser_nonpriv_group" {
  user   = aws_iam_user.attacker["fp_adduser_nonpriv_group"].name
  groups = [aws_iam_group.admin_group.name]
}

# A DECOY ROLE that exists ONLY to be the IAM principal named in trust_mismatch_target's trust
# below (so that trust names a REAL same-account principal — keeping the FP exercising the
# "trust names a different principal than the attacker" case, not just a service-only trust).
# It is a ROLE, not a user, on purpose: under F6 it gains a validated STS_ASSUMEROLE edge to the
# admin trust_mismatch_target purely from the exact-ARN direct trust → it becomes _is_privileged.
# That privilege is HARMLESS here because:
#   - The broad principal-access methods (iam_create_access_key / iam_create_login_profile) gate on
#     target ARN CONTAINS ':user/', so they CANNOT target a role — a privileged role is not a
#     principal-access target.
#   - This role's OWN trust is a BENIGN service principal (ec2.amazonaws.com), not :root and not any
#     attacker, so the IAM evaluator emits NO inbound STS_ASSUMEROLE edge for any attacker → the
#     STS_ASSUMEROLE-gated role methods (iam_put_role_policy / iam_attach_role_policy) cannot draw a
#     CAN_PRIVESC edge into it either.
# Its only OUTBOUND CAN_PRIVESC is the legit CAN_PRIVESC{sts:AssumeRole} -> trust_mismatch_target
# (a real F6 direct-trust path; that target is already no-fan-out allowlisted).
# Its INBOUND CAN_PRIVESC edges are the broad role-fan-out edges that land on EVERY modifiable /
# privileged role — because it is _is_privileged (the outbound F6 edge above) AND carries a non-empty
# service trust (trusted_services=[ec2.amazonaws.com]):
#   - iam_update_assume_role_policy (MEDIUM — fails open on privilege; privileged target → medium),
#   - passrole_modify_policy (HIGH — its service-trust OR-leg is satisfied by trusted_services=[ec2]),
#   - update_assume_role_passrole_service (MEDIUM — privileged target + PassRole).
# These are the SAME broad role-fan-out edge classes already accepted for the sibling decoy roles
# wrong_service_target and service_only_trust_role, which is WHY this role is added to the test's
# decoyARNs allowlist (no-fan-out-allowlisted decoy targets, not masking a real finding). It holds NO
# policies.
resource "aws_iam_role" "trust_mismatch_decoy" {
  name = "${local.prefix}-trust-mismatch-decoy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = local.tags
}

# DECOY: a role whose trust names ONLY the trust_mismatch_decoy ROLE (not :root and not any
# attacker) → no STS_ASSUMEROLE edge is emitted for an arbitrary attacker (the trust does not
# allow them). Backs the AssumeRole trust-policy-mismatch FP (fp_putrolepolicy_not_assumable): a
# PutRolePolicy attacker scoped to this role has the modify edge but no assume path, so the method
# must NOT fire. It is admin so the FP is purely about TRUST, not privilege.
resource "aws_iam_role" "trust_mismatch_target" {
  name = "${local.prefix}-trust-mismatch"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_role.trust_mismatch_decoy.arn }
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

# DECOY: an admin role whose trust names ONLY a service principal (lambda) — never :root and
# never an attacker user. The evaluator emits an STS_ASSUMEROLE edge only when the role's trust
# allows the principal AND the principal holds sts:AssumeRole, so NO attacker gets an
# STS_ASSUMEROLE edge to this role. Backs the iam_attach_role_policy trust-backed FP: an attacker
# scoping AttachRolePolicy to this role has the modify edge but no assume path, so the method must
# NOT fire. It is admin so the suppression is purely about the missing assume path, not target privilege.
resource "aws_iam_role" "service_only_trust_role" {
  name = "${local.prefix}-service-only-trust"
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
resource "aws_iam_role_policy_attachment" "service_only_trust_role" {
  role       = aws_iam_role.service_only_trust_role.name
  policy_arn = local.admin_policy
}

# An admin role whose trust policy EXPLICITLY names the attacker_trusted attacker user's ARN, and
# that attacker holds sts:AssumeRole scoped to it → the evaluator emits a validated STS_ASSUMEROLE
# edge from that attacker to this role → sts_assume_role fires (TP), completing the
# trust-mismatch matrix's "trusts-attacker-explicitly = TP" cell.
resource "aws_iam_role" "attacker_trusted_role" {
  name = "${local.prefix}-attacker-trusted"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.attacker["sts_assume_attacker_trusted"].arn }
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "attacker_trusted_role" {
  role       = aws_iam_role.attacker_trusted_role.name
  policy_arn = local.admin_policy
}

# F6: an admin role whose trust policy DIRECTLY names the sts_assume_direct_trust attacker's exact
# ARN. That attacker holds NO sts:AssumeRole grant — same-account exact-ARN trust is sufficient
# ALONE (AWS allows the assumption with no identity entitlement), so the evaluator emits a validated
# STS_ASSUMEROLE edge from the direct trust → sts_assume_role fires (TP) PURELY from the direct-trust
# path. This is the new direct-trust e2e scenario; it does not disturb admin_target (:root trust) or
# attacker_trusted_role (trust + grant).
resource "aws_iam_role" "direct_trust_admin_role" {
  name = "${local.prefix}-direct-trust-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.attacker["sts_assume_direct_trust"].arn }
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "direct_trust_admin_role" {
  role       = aws_iam_role.direct_trust_admin_role.name
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
# Phase-2a REAL backing service resources for the existing-compute HAS_ROLE methods.
#
# Each resource RUNS AS a privileged role so the recon collectors enumerate it,
# resource_service_role builds a real (Resource)-[:HAS_ROLE]->(role) edge on REAL CloudControl-
# shaped data, and the matching existing-compute privesc method re-points its CAN_PRIVESC edge
# at that role on real collected data rather than a synthetic stand-in.
#
# All run the compute_admin role (an admin role, _is_admin=true → method severity high) EXCEPT
# the Batch job definition, whose jobRoleArn must be the ecs-tasks-trusting svcadmin role (the
# batch_submit_job re-point targets tgtServiceRole["ecstasks"]).
#
# Only the cheap, free-at-rest, no-VPC, no-image types are provisioned here:
#   CFN stack/stackset, Batch job def, ECS task def, SFN state machine, Glue job, CodeBuild
#   project. The heavy/costly types (App Runner = needs a running container image; SageMaker
#   notebook instance = bills while running; Glue dev endpoint = needs a VPC + bills hourly;
#   Bedrock AgentCore code interpreter = no Terraform provider resource) are KEPT synthetic in
#   the Go harness with a documented comment — their collectors are unit-tested.
# =============================================================================

# --- CloudFormation stack (backs cloudform_update_stack + cloudform_changeset; RoleARN in
#     DescribeStacks → resource_service_role HAS_ROLE → compute_admin). Minimal template: a
#     WaitConditionHandle is free, provisions instantly, and needs no role action at create
#     time (so the service role's lack of cloudformation-specific perms is irrelevant). ---
resource "aws_cloudformation_stack" "compute" {
  name         = "${local.prefix}-compute-stack"
  iam_role_arn = aws_iam_role.compute_admin.arn
  template_body = jsonencode({
    Resources = {
      Wait = { Type = "AWS::CloudFormation::WaitConditionHandle" }
    }
  })
  tags = local.tags
}

# --- CloudFormation stack set (backs cloudform_update_stackset; AdministrationRoleARN in
#     DescribeStackSet → resource_service_role HAS_ROLE → compute_admin). SELF_MANAGED
#     permissions, no instances → free + instant. ---
resource "aws_cloudformation_stack_set" "compute" {
  name                    = "${local.prefix}-compute-stackset"
  permission_model        = "SELF_MANAGED"
  administration_role_arn = aws_iam_role.compute_admin.arn
  template_body = jsonencode({
    Resources = {
      Wait = { Type = "AWS::CloudFormation::WaitConditionHandle" }
    }
  })
  tags = local.tags
}

# --- Batch job definition (backs batch_submit_job; jobRoleArn → resource_service_role
#     HAS_ROLE → the ecs-tasks-trusting svcadmin role, which is what the batch_submit_job
#     re-point's trust + privileged-target guards require). FARGATE container definition —
#     a job DEFINITION needs NO compute environment / queue / VPC (those are only needed to
#     RUN a job), so this is free + instant. executionRoleArn is the same svcadmin role. ---
resource "aws_batch_job_definition" "compute" {
  name                  = "${local.prefix}-compute-jobdef"
  type                  = "container"
  platform_capabilities = ["FARGATE"]
  container_properties = jsonencode({
    image                        = "public.ecr.aws/amazonlinux/amazonlinux:2"
    command                      = ["echo", "aurelian-pathfinding"]
    jobRoleArn                   = aws_iam_role.service_admin["ecstasks"].arn
    executionRoleArn             = aws_iam_role.service_admin["ecstasks"].arn
    fargatePlatformConfiguration = { platformVersion = "LATEST" }
    resourceRequirements = [
      { type = "VCPU", value = "0.25" },
      { type = "MEMORY", value = "512" },
    ]
    networkConfiguration = { assignPublicIp = "DISABLED" }
  })
  tags = local.tags
}

#==============================================================================
# F2: ECS CLUSTER (backs the cluster-scoped ecs:ExecuteCommand path / ecs-006)
# Expected: COLLECTED as AWS::ECS::Cluster + base ECS_EXECUTECOMMAND edge target
#
# The ECSClusterEnumerator (F2) collects this as an AWS::ECS::Cluster :Resource node.
# A cluster-scoped ecs:ExecuteCommand grant (see the ecs_execute_command_cluster attacker)
# resolves against this concrete cluster ARN → the base ECS_EXECUTECOMMAND edge forms to this
# node → the ecs_execute_command privesc enricher fires (joins the task def HAS_ROLE → task
# role independently). Before F2 no cluster node existed, so a cluster-scoped grant produced NO
# base edge → ecs-006 was a miss. An empty cluster is free at rest (no running tasks).
# The cluster name carries the run prefix so its ARN is kept by the harness's
# resourceReferencesPrefix bound and added to all_arns.
#==============================================================================
resource "aws_ecs_cluster" "exec" {
  name = "${local.prefix}-exec-cluster"
  tags = local.tags
}

# --- ECS task definition (backs ecs_execute_command; taskRoleArn + executionRoleArn →
#     resource_service_role HAS_ROLE → compute_admin). A task DEFINITION needs no running
#     task / cluster, so it is free. FARGATE-compatible. ---
resource "aws_ecs_task_definition" "compute" {
  family                   = "${local.prefix}-compute-taskdef"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  task_role_arn            = aws_iam_role.compute_admin.arn
  execution_role_arn       = aws_iam_role.compute_admin.arn
  container_definitions = jsonencode([{
    name      = "main"
    image     = "public.ecr.aws/amazonlinux/amazonlinux:2"
    essential = true
  }])
  tags = local.tags
}

# --- Step Functions state machine (backs stepfunctions_update; roleArn → resource_service_role
#     HAS_ROLE → compute_admin). STANDARD type is free at rest (pay only per state transition,
#     and this machine is never executed). compute_admin trusts states.amazonaws.com so
#     CreateStateMachine's trust validation passes. ---
resource "aws_sfn_state_machine" "compute" {
  name     = "${local.prefix}-compute-sfn"
  role_arn = aws_iam_role.compute_admin.arn
  definition = jsonencode({
    Comment = "aurelian pathfinding fixture — never executed"
    StartAt = "Done"
    States  = { Done = { Type = "Pass", End = true } }
  })
  tags = local.tags
}

# --- Glue job (backs glue_update_job + glue_updatejob_startjobrun + glue_updatejob_trigger;
#     Role → resource_service_role HAS_ROLE → compute_admin). role_arn MUST be the FULL ARN
#     (the collector captures Job.Role; only the ARN form substring-matches a role node — a
#     role NAME is fail-closed by design). Needs an S3 script object (free). compute_admin
#     trusts glue.amazonaws.com so CreateJob's trust validation passes. Free unless run. ---
resource "aws_s3_bucket" "glue_scripts" {
  bucket        = "${local.prefix}-glue-scripts"
  force_destroy = true
  tags          = local.tags
}
resource "aws_s3_object" "glue_script" {
  bucket  = aws_s3_bucket.glue_scripts.id
  key     = "placeholder.py"
  content = "# aurelian pathfinding fixture placeholder\n"
}
resource "aws_glue_job" "compute" {
  name         = "${local.prefix}-compute-glue"
  role_arn     = aws_iam_role.compute_admin.arn
  glue_version = "4.0"
  command {
    script_location = "s3://${aws_s3_bucket.glue_scripts.bucket}/${aws_s3_object.glue_script.key}"
    python_version  = "3"
  }
  default_arguments = { "--job-language" = "python" }
  tags              = local.tags
}

# --- CodeBuild project (backs codebuild_start_build; ServiceRole → resource_service_role
#     HAS_ROLE → compute_admin). NO_SOURCE source needs no repo; a tiny inline buildspec
#     satisfies the NO_SOURCE requirement. compute_admin trusts codebuild.amazonaws.com so
#     CreateProject's trust validation passes. Free unless built. ---
resource "aws_codebuild_project" "compute" {
  name         = "${local.prefix}-compute-codebuild"
  service_role = aws_iam_role.compute_admin.arn
  artifacts {
    type = "NO_ARTIFACTS"
  }
  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"
  }
  source {
    type      = "NO_SOURCE"
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo aurelian\n"
  }
  tags = local.tags
}

# =============================================================================
# Branch-coverage shared targets + real backing resources.
#
# Each block backs a labCase BRANCH (other rows cover a DIFFERENT branch of the same
# method YAML). All collectors / transformer
# promotions / enrichers these rely on already exist and are wired into graph.go.
# =============================================================================

#==============================================================================
# SSM via the AmazonSSMManagedInstanceCore MANAGED POLICY (not ssm trust).
# An admin role that TRUSTS ec2.amazonaws.com (NOT ssm) and attaches
# AmazonSSMManagedInstanceCore. set_ssm_enabled_roles.yaml flags it _ssm_enabled via the
# managed-policy CONTAINS clause (the canonical real-world EC2->SSM path), so ssm_send_command
# / ssm_start_session fire on it even though it does not trust ssm. The prior ssm cases use
# compute_admin, which TRUSTS ssm — this is the distinct managed-policy path.
#==============================================================================
resource "aws_iam_role" "ssm_managed_admin" {
  name = "${local.prefix}-ssm-managed-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" } # NOT ssm — SSM capability comes from the managed policy
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "ssm_managed_admin_admin" {
  role       = aws_iam_role.ssm_managed_admin.name
  policy_arn = local.admin_policy
}
resource "aws_iam_role_policy_attachment" "ssm_managed_admin_ssmcore" {
  role       = aws_iam_role.ssm_managed_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_instance_profile" "ssm_managed" {
  name = "${local.prefix}-ssm-managed"
  role = aws_iam_role.ssm_managed_admin.name
}
# A free-at-rest t3.micro running the ssm-managed admin role, so the EC2-instance collector
# enumerates it and resource_to_role builds (instance)-[:HAS_ROLE]->(ssm_managed_admin).
resource "aws_instance" "ssm_managed" {
  ami                  = data.aws_ami.al2023.id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.ssm_managed.name
  tags                 = merge(local.tags, { Name = "${local.prefix}-ssm-managed" })
}

#==============================================================================
# Cognito UNAUTHENTICATED identity pool (unauth-relax branch).
# A real identity pool with AllowUnauthenticatedIdentities=true bound to a cognito-trusting
# admin role. The cognito_set_identity_pool_roles unauth branch fires for an attacker holding
# PassRole + SetIdentityPoolRoles but NO GetId/GetCredentials, gated on the connected
# (IdentityPool{AllowUnauthenticatedIdentities:true})-[:HAS_ROLE]->(role) edge. The prior
# cognito case requires GetId+GetCredentials (the authenticated branch).
#==============================================================================
resource "aws_iam_role" "cognito_unauth_admin" {
  name = "${local.prefix}-cognito-unauth-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "cognito-identity.amazonaws.com" }
      Condition = {
        StringEquals = {
          "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.unauth.id
        }
      }
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "cognito_unauth_admin" {
  role       = aws_iam_role.cognito_unauth_admin.name
  policy_arn = local.admin_policy
}
resource "aws_cognito_identity_pool" "unauth" {
  identity_pool_name               = "${local.prefix}-unauth"
  allow_unauthenticated_identities = true
  tags                             = local.tags
}
resource "aws_cognito_identity_pool_roles_attachment" "unauth" {
  identity_pool_id = aws_cognito_identity_pool.unauth.id
  roles = {
    authenticated   = aws_iam_role.cognito_unauth_admin.arn
    unauthenticated = aws_iam_role.cognito_unauth_admin.arn
  }
}

#==============================================================================
# An AUTHENTICATED-ONLY identity pool (AllowUnauthenticatedIdentities=false) bound to
# a cognito admin role. The fp_cognito_authpool_no_getid attacker holds PassRole +
# SetIdentityPoolRoles but NO GetId/GetCredentials, so neither the authenticated branch (needs
# those two perms) nor the unauth-relax branch (needs AllowUnauthenticatedIdentities=true)
# is satisfied -> the method must NOT fire. Proves the unauth relax is scoped, not blanket.
#==============================================================================
resource "aws_iam_role" "cognito_authonly_admin" {
  name = "${local.prefix}-cognito-authonly-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "cognito-identity.amazonaws.com" }
      Condition = {
        StringEquals = {
          "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.authonly.id
        }
      }
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "cognito_authonly_admin" {
  role       = aws_iam_role.cognito_authonly_admin.name
  policy_arn = local.admin_policy
}
resource "aws_cognito_identity_pool" "authonly" {
  identity_pool_name               = "${local.prefix}-authonly"
  allow_unauthenticated_identities = false
  tags                             = local.tags
}
resource "aws_cognito_identity_pool_roles_attachment" "authonly" {
  identity_pool_id = aws_cognito_identity_pool.authonly.id
  roles = {
    authenticated = aws_iam_role.cognito_authonly_admin.arn
  }
}

#==============================================================================
# An EXISTING EC2 launch template referencing the compute_admin instance profile.
# The launch-template collector enumerates it; the transformer promotes IamInstanceProfile;
# set_launch_template_role.yaml builds (LaunchTemplate)-[:HAS_ROLE]->(compute_admin). The
# ec2_launch_template_version existing-template UNION branch re-points its CAN_PRIVESC edge at
# that role for an attacker holding CreateLaunchTemplateVersion+ModifyLaunchTemplate (NO
# PassRole). The prior launch-template case is the new-passrole branch.
#==============================================================================
resource "aws_launch_template" "existing" {
  name = "${local.prefix}-existing-lt"
  iam_instance_profile {
    arn = aws_iam_instance_profile.compute_admin.arn
  }
  tags = local.tags
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
    iam_put_role_policy           = [{ actions = ["iam:PutRolePolicy", "sts:AssumeRole"], resources = ["*"] }]
    iam_attach_role_policy        = [{ actions = ["iam:AttachRolePolicy", "sts:AssumeRole"], resources = ["*"] }]
    iam_update_assume_role_policy = [{ actions = ["iam:UpdateAssumeRolePolicy"], resources = ["*"] }]
    sts_assume_role               = [{ actions = ["sts:AssumeRole"], resources = ["*"] }]
    # passrole_modify_policy modifies the role's policy AND must be able to USE the role. The
    # admin_target trusts only :root (no service), so the only usable assume path is sts:AssumeRole —
    # the evaluator emits the validated STS_ASSUMEROLE edge from this grant + the :root trust, which
    # the enricher's assume-gate requires. (Twin of the iam_put_role_policy / iam_attach_role_policy
    # attackers above, which also carry sts:AssumeRole.)
    passrole_modify_policy              = [{ actions = ["iam:PassRole", "iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy", "sts:AssumeRole"], resources = ["*"] }]
    update_assume_role_passrole_service = [{ actions = ["iam:UpdateAssumeRolePolicy", "iam:PassRole"], resources = ["*"] }]

    # F6 direct-trust path: this attacker has NO sts:AssumeRole grant (and no other privesc-relevant
    # identity perm) — only a benign read. It is DIRECTLY NAMED by ARN in direct_trust_admin_role's
    # trust policy below. Same-account exact-ARN trust is sufficient ALONE (AWS allows the assumption
    # with no identity grant), so the evaluator emits a validated STS_ASSUMEROLE edge purely from the
    # direct trust → sts_assume_role fires (TP) to direct_trust_admin_role. Exercises ONLY the F6
    # direct-trust path (distinct from sts_assume_role, which relies on a grant + :root trust, and
    # from sts_assume_attacker_trusted, which has BOTH a trust naming it AND a grant).
    sts_assume_direct_trust = [{ actions = ["sts:GetCallerIdentity"], resources = ["*"] }]

    # Trust-mismatch matrix: a role that EXPLICITLY names this attacker in its trust policy, paired
    # with sts:AssumeRole on it → the evaluator emits a validated STS_ASSUMEROLE edge → sts_assume_role
    # fires (TP) to that role. The ":root-trusted same-account = TP" matrix cell is already covered by
    # the sts_assume_role attacker above (admin_target trusts :root). sts:AssumeRole is on "*" (the
    # method joins the STS_ASSUMEROLE edge, which already encodes identity AND trust, to the victim).
    sts_assume_attacker_trusted = [{ actions = ["sts:AssumeRole"], resources = ["*"] }]

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
    lambda_update_code        = [{ actions = ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"], resources = ["*"] }]
    lambda_updatecode_invoke  = [{ actions = ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"], resources = ["*"] }]
    lambda_add_permission     = [{ actions = ["lambda:UpdateFunctionCode", "lambda:AddPermission"], resources = ["*"] }]
    lambda_create_esm         = [{ actions = ["lambda:UpdateFunctionCode", "lambda:CreateEventSourceMapping"], resources = ["*"] }]
    ec2_modify_attribute      = [{ actions = ["ec2:ModifyInstanceAttribute", "ec2:StopInstances", "ec2:StartInstances"], resources = ["*"] }]
    ec2_instance_connect      = [{ actions = ["ec2-instance-connect:SendSSHPublicKey"], resources = ["*"] }]
    ec2_ssm_association       = [{ actions = ["ssm:CreateAssociation"], resources = ["*"] }]
    ssm_send_command          = [{ actions = ["ssm:SendCommand"], resources = ["*"] }]
    ssm_start_session         = [{ actions = ["ssm:StartSession"], resources = ["*"] }]
    cloudform_update_stack    = [{ actions = ["cloudformation:UpdateStack"], resources = ["*"] }]
    cloudform_update_stackset = [{ actions = ["cloudformation:UpdateStackSet"], resources = ["*"] }]
    codebuild_start_build     = [{ actions = ["codebuild:StartBuild"], resources = ["*"] }]
    codedeploy_create_deploy  = [{ actions = ["codedeploy:CreateDeployment"], resources = ["*"] }]
    apprunner_update_service  = [{ actions = ["apprunner:UpdateService"], resources = ["*"] }]
    ecs_execute_command       = [{ actions = ["ecs:ExecuteCommand", "ecs:DescribeTasks"], resources = ["*"] }]
    # F2 (ecs-006): ecs:ExecuteCommand scoped ONLY to the cluster ARN (and its tasks) — NOT a
    #     wildcard, NOT a task-def ARN. This specifically exercises the cluster-node path F2 adds:
    #     the grant resolves against the AWS::ECS::Cluster node the ECSClusterEnumerator collects,
    #     so the base ECS_EXECUTECOMMAND edge forms to the cluster and the enricher reaches the
    #     task def's task role (compute_admin) via HAS_ROLE. Mirrors the real ecs-006 lab.
    ecs_execute_command_cluster = [{
      actions = ["ecs:ExecuteCommand", "ecs:DescribeTasks"]
      resources = [
        aws_ecs_cluster.exec.arn,
        "arn:aws:ecs:${var.region}:${local.account_id}:task/${aws_ecs_cluster.exec.name}/*",
      ]
    }]
    stepfunctions_update       = [{ actions = ["states:UpdateStateMachine", "states:StartExecution"], resources = ["*"] }]
    glue_update_dev_endpoint   = [{ actions = ["glue:UpdateDevEndpoint"], resources = ["*"] }]
    glue_update_job            = [{ actions = ["glue:UpdateJob"], resources = ["*"] }]
    glue_updatejob_startjobrun = [{ actions = ["glue:UpdateJob", "glue:StartJobRun"], resources = ["*"] }]
    glue_updatejob_trigger     = [{ actions = ["glue:UpdateJob", "glue:CreateTrigger"], resources = ["*"] }]
    sagemaker_lifecycle        = [{ actions = ["sagemaker:UpdateNotebookInstanceLifecycleConfig"], resources = ["*"] }]
    sagemaker_presigned        = [{ actions = ["sagemaker:CreatePresignedNotebookInstanceUrl"], resources = ["*"] }]

    # ---- Branch-coverage TP attackers ----
    # Conditional PassRole — StringEquals { iam:PassedToService = lambda.amazonaws.com } +
    #     lambda:CreateFunction. The evaluator's permissive-when-absent handling of
    #     iam:PassedToService keeps the IAM_PASSROLE edge, and iam_pass_role_lambda re-checks the
    #     role's lambda trust -> CAN_PRIVESC forms to the lambda svcadmin role.
    iam_pass_role_lambda_cond = [
      { actions = ["iam:PassRole"], resources = ["*"], condition = { StringEquals = { "iam:PassedToService" = "lambda.amazonaws.com" } } },
      { actions = ["lambda:CreateFunction"], resources = ["*"] },
    ]
    # SSM via managed-policy (ec2-trusting role + AmazonSSMManagedInstanceCore). Same actions
    #     as the other ssm cases; the distinct path is the TARGET role (ssm_managed_admin) reached
    #     via the ec2 instance whose role is _ssm_enabled by the managed-policy flag.
    ssm_managed_send_command  = [{ actions = ["ssm:SendCommand"], resources = ["*"] }]
    ssm_managed_start_session = [{ actions = ["ssm:StartSession"], resources = ["*"] }]
    # Existing-compute Lambda on the REAL collected aws_lambda_function.compute (no resource
    #     policy). Distinct from lambda_update_code (synthetic stand-in): asserts the REAL
    #     (fn)-[:HAS_ROLE]->(compute_admin) path.
    lambda_update_code_real = [{ actions = ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"], resources = ["*"] }]
    # Glue new-passrole UNION branch — PassRole(glue) + UpdateJob + StartJobRun with NO
    #     pre-existing Glue job. Target = the passed glue svcadmin role (via IAM_PASSROLE).
    glue_passrole_updatejob = [{ actions = ["iam:PassRole", "glue:UpdateJob", "glue:StartJobRun"], resources = ["*"] }]
    # Existing-template branch — CreateLaunchTemplateVersion + ModifyLaunchTemplate, NO
    #      PassRole. Target = compute_admin via (LaunchTemplate)-[:HAS_ROLE]->(role).
    ec2_launch_template_existing = [{ actions = ["ec2:CreateLaunchTemplateVersion", "ec2:ModifyLaunchTemplate"], resources = ["*"] }]
    # Cognito unauth-relax — PassRole + SetIdentityPoolRoles, NO GetId/GetCredentials. Fires
    #      only because the bound pool allows unauthenticated identities.
    cognito_unauth_pool = [{ actions = ["iam:PassRole", "cognito-identity:SetIdentityPoolRoles"], resources = ["*"] }]

    # ---- Service-wildcard fail-open (target = permission stub) ----
    batch_submit_job    = [{ actions = ["batch:SubmitJob"], resources = ["*"] }]
    bedrock_invoke      = [{ actions = ["bedrock-agentcore:StartCodeInterpreterSession", "bedrock-agentcore:InvokeCodeInterpreter"], resources = ["*"] }]
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
    # F2 collector-precision FP: a benign principal that can READ the ECS cluster but holds NO
    #     ecs:ExecuteCommand. Collecting the cluster (F2) must NOT fan out a spurious
    #     ECS_EXECUTECOMMAND edge to this principal (only the action grant creates that edge). The
    #     harness asserts this attacker has ZERO ECS_EXECUTECOMMAND edges to the cluster node.
    fp_ecs_no_execute_command = [{ actions = ["ecs:DescribeClusters", "ecs:ListClusters"], resources = ["*"] }]

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

    # ---- Trust-backed direct-takeover FPs ----
    # iam_attach_role_policy / iam_put_role_policy require BOTH a validated STS_ASSUMEROLE edge to the
    # victim AND the modify-permission edge to the SAME victim. AttachRolePolicy / PutRolePolicy are
    # SCOPED to a decoy role the attacker CANNOT assume (the evaluator emits no STS_ASSUMEROLE edge to
    # it), so the modify edge points only at the un-assumable decoy → neither leg coincides on any
    # role → 0 edges. Removing the assume-path requirement would let the method fire on the decoy
    # (proving the FP is sound). Twins: the iam_attach_role_policy / iam_put_role_policy attackers
    # above fire on the :root-trusted admin_target (both legs coincide there).
    #
    # NOTE — NO sound sts_assume_role / iam_update_assume_role_policy scoped FP exists in this
    # fixture: sts_assume_role now joins the validated STS_ASSUMEROLE edge directly to the victim
    # (the edge already encodes identity AND trust), and admin_target trusts :root, so every attacker
    # holding sts:AssumeRole genuinely escalates to admin_target (a real TP). iam_update_assume_role_policy
    # rewrites the role's trust to insert the attacker (self-sufficient, no pre-existing assume-path
    # precondition), so a service-only-trusted role is still a genuine takeover (TP). Both are reported,
    # not authored as unsound FPs.

    # service-only trust: the role trusts ONLY the lambda service (no :root, no attacker) → the
    # evaluator emits no STS_ASSUMEROLE edge to it → AttachRolePolicy scoped to it cannot land on an
    # assumable role.
    fp_attachrolepolicy_service_only = [{ actions = ["iam:AttachRolePolicy"], resources = [aws_iam_role.service_only_trust_role.arn] }]

    # not-assumable: trust_mismatch_target trusts ONLY the trust_mismatch_decoy ROLE, not :root and
    # not this attacker → no STS_ASSUMEROLE edge for this attacker → PutRolePolicy scoped to it
    # cannot land on an assumable role.
    fp_putrolepolicy_not_assumable = [{ actions = ["iam:PutRolePolicy"], resources = [aws_iam_role.trust_mismatch_target.arn] }]

    # ---- Self-escalation FPs ----
    # Holds iam:CreatePolicyVersion on a self-attached customer policy, but ALSO carries
    # AdministratorAccess (attached separately below) → set_admin marks it _is_admin → the
    # self-loop methods' admin-as-source guard (attacker._is_admin <> true) suppresses (an admin
    # gains nothing by self-escalating). Twin: the iam_create_policy_version attacker (non-admin).
    fp_already_admin = [{ actions = ["iam:CreatePolicyVersion"], resources = ["*"] }]

    # Holds iam:AddUserToGroup but the only group it can join is the NON-privileged member_group
    # (wired below); the admin group it could join, it is already a member of (wired below). The
    # guard requires a PRIVILEGED group the attacker is NOT already in → suppressed. Twin: the
    # iam_add_user_to_group attacker (joins the admin_group, not already a member).
    fp_adduser_nonpriv_group = [{ actions = ["iam:AddUserToGroup"], resources = ["*"] }]

    # Holds iam:PutGroupPolicy but is NOT a member of any group, so writing an inline policy to a
    # group changes its own effective permissions not at all → the guard's membership requirement
    # (GroupName IN attacker.GroupList) is unmet → suppressed. Twin: the iam_put_group_policy
    # attacker (a member of member_group).
    fp_putgrouppolicy_not_member = [{ actions = ["iam:PutGroupPolicy"], resources = ["*"] }]

    # ---- Login-profile / access-key FPs (live tri-state from the GAAD collector) ----
    # iam:UpdateLoginProfile scoped to noprofile_user (a privileged user with NO console login
    # profile). The collector's GetLoginProfile returns NoSuchEntity → HasLoginProfile=false → the
    # guard suppresses. Twin: the iam_update_login_profile attacker (priv_user HAS a profile).
    fp_updateloginprofile_no_profile = [{ actions = ["iam:UpdateLoginProfile"], resources = [aws_iam_user.noprofile_user.arn] }]

    # iam:CreateAccessKey+DeleteAccessKey scoped to twokey_user (a privileged user already holding
    # 2 active access keys). The collector's ListAccessKeys returns AccessKeyCount=2 → the guard
    # (AccessKeyCount < 2) suppresses. Twin: the iam_create_access_key attacker (priv_user has <2).
    fp_createaccesskey_two_keys = [{ actions = ["iam:CreateAccessKey", "iam:DeleteAccessKey"], resources = [aws_iam_user.twokey_user.arn] }]

    # G1 FP twin (login-profile already-exists). iam:CreateLoginProfile+iam:UpdateLoginProfile SCOPED
    # to priv_user — a PRIVILEGED user that ALREADY has a console login profile
    # (aws_iam_user_login_profile.priv_user). The GAAD collector's iam:GetLoginProfile SUCCEEDS →
    # HasLoginProfile=true → the iam_create_login_profile guard coalesce(target.HasLoginProfile,
    # false) = false is unmet → the method SUPPRESSES (CreateLoginProfile on a user that already has
    # one returns EntityAlreadyExists). This is the EXACT INVERSE of the iam_create_login_profile TP
    # attacker (scoped to "*", lands on noprofile_user which has NO profile). priv_user is admin, so
    # the suppression is purely about the existing profile, not target privilege. Removing ONLY the
    # G1 HasLoginProfile guard would let this fire on priv_user, proving the FP is sound (not vacuous).
    fp_createloginprofile_has_profile = [{ actions = ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"], resources = [aws_iam_user.priv_user.arn] }]

    # G2 FP twin (single-version policy → SetDefaultPolicyVersion is inert). iam:SetDefaultPolicyVersion
    # on a self-attached customer-managed policy that has only ONE version (aws_iam_policy.single_ver,
    # attached below). The transformer surfaces policy.policy_version_count = 1 → the
    # iam_set_default_policy_version guard coalesce(policy.policy_version_count, 2) > 1 is unmet → the
    # method SUPPRESSES (there is no non-default version to activate, so SetDefaultPolicyVersion grants
    # no new privilege). Twin: the iam_set_default_policy_version TP attacker (self-attaches the
    # multi-version aws_iam_policy.custom). Removing ONLY the G2 version-count guard would let this fire,
    # proving the FP is sound.
    fp_setdefaultversion_single_version = [{ actions = ["iam:SetDefaultPolicyVersion"], resources = ["*"] }]

    # ---- Branch-coverage FP attackers ----
    # Conditional PassRole (PassedToService=lambda) but NO lambda:CreateFunction ->
    # iam_pass_role_lambda must NOT fire (the conditional-PassRole path still requires the
    # consuming action; the IAM_PASSROLE edge forms but there is no create primitive).
    fp_passrole_cond_only = [
      { actions = ["iam:PassRole"], resources = ["*"], condition = { StringEquals = { "iam:PassedToService" = "lambda.amazonaws.com" } } },
    ]
    # The ssm-managed instance + _ssm_enabled role exist, but this attacker holds
    # NEITHER ssm:SendCommand NOR ssm:StartSession (only a read action) -> ssm_send_command must
    # NOT fire (missing-permission; isolates the action requirement from the HAS_ROLE/_ssm_enabled
    # preconditions, which ARE satisfied).
    fp_ssm_managed_no_send = [{ actions = ["ssm:DescribeInstanceInformation"], resources = ["*"] }]
    # PassRole + SetIdentityPoolRoles scoped at the AUTH-ONLY pool's role, NO
    # GetId/GetCredentials. The authenticated branch needs those two perms; the unauth-relax
    # branch needs AllowUnauthenticatedIdentities=true (the bound pool is false) -> NO edge.
    fp_cognito_authpool_no_getid = [{ actions = ["iam:PassRole", "cognito-identity:SetIdentityPoolRoles"], resources = ["*"] }]
    # PassRole(ec2) ONLY, no CreateLaunchTemplateVersion/ModifyLaunchTemplate ->
    # neither ec2_launch_template_version branch (both require the two edit actions) fires.
    fp_ec2_lt_passrole_only = [{ actions = ["iam:PassRole"], resources = ["*"] }]
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
    # A statement may carry an optional `condition` map (operator -> { key -> value }), emitted
    # as a Condition block ONLY when present — condition-less statements emit no Condition block.
    # Used by the conditional-PassRole TP/FP: a PassRole scoped by
    # StringEquals { iam:PassedToService = lambda.amazonaws.com }. The evaluator treats
    # iam:PassedToService as permissive-when-absent (isPassRolePermissiveKey), so the IAM_PASSROLE
    # edge still forms and iam_pass_role_lambda re-checks the role's lambda trust downstream.
    Statement = [for s in each.value : merge(
      {
        Effect   = "Allow"
        Action   = s.actions
        Resource = s.resources
      },
      lookup(s, "condition", null) == null ? {} : { Condition = s.condition },
    )]
  })
}

# The customer-managed policy attached to the CreatePolicyVersion / SetDefaultPolicyVersion
# attackers (so set_admin sees nothing, but the self-loop guard's attached-to-attacker
# CONTAINS check passes). Grants only a harmless read.
#
# This policy carries TWO versions (the inline `policy` body is v1; null_resource.custom_v2 below
# creates a non-default v2 via the AWS CLI — the AWS provider has no managed resource for policy
# versions). The transformer surfaces policy.policy_version_count = 2, which satisfies BOTH:
#   - iam_create_policy_version's guard `policy_version_count < 5` (2 < 5 → TP fires), and
#   - iam_set_default_policy_version's G2 guard `coalesce(policy.policy_version_count, 2) > 1`
#     (2 > 1 → TP fires: there IS a non-default version to activate).
# A SINGLE-version policy would (correctly) suppress the SetDefaultPolicyVersion TP under G2 — that
# inert case is the new fp_setdefaultversion_single_version FP twin (aws_iam_policy.single_ver below).
resource "aws_iam_policy" "custom" {
  name = "${local.prefix}-custom"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:GetUser"], Resource = "*" }]
  })
}
# A second (non-default) version of the custom policy so policy_version_count = 2 (>1). This is what
# makes the iam_set_default_policy_version TP legitimately escalatory: there is a non-default version
# to activate. --no-set-as-default keeps v1 the default (the inline body) so this is purely a
# version-count signal, not a behavior change to the attached policy. The retry loop tolerates IAM
# eventual consistency right after the policy is created; the `|| true` makes a re-run idempotent
# (a policy that already has v2 simply ignores a duplicate). Created via the CLI because the AWS
# provider exposes no aws_iam_policy_version resource.
resource "null_resource" "custom_v2" {
  depends_on = [aws_iam_policy.custom]
  triggers   = { policy_arn = aws_iam_policy.custom.arn }
  provisioner "local-exec" {
    command = <<-EOT
      for i in 1 2 3 4 5; do
        aws iam create-policy-version \
          --policy-arn ${aws_iam_policy.custom.arn} \
          --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListUsers"],"Resource":"*"}]}' \
          --no-set-as-default && break
        echo "create-policy-version attempt $i failed, retrying in $((i * 2))s..."
        sleep $((i * 2))
      done || true
    EOT
  }
}
resource "aws_iam_user_policy_attachment" "create_policy_version_custom" {
  user       = aws_iam_user.attacker["iam_create_policy_version"].name
  policy_arn = aws_iam_policy.custom.arn
}
resource "aws_iam_user_policy_attachment" "set_default_policy_version_custom" {
  user       = aws_iam_user.attacker["iam_set_default_policy_version"].name
  policy_arn = aws_iam_policy.custom.arn
}

# G2 FP: a customer-managed policy with a SINGLE version (only the inline body, no
# aws_iam_policy_version). The transformer surfaces policy.policy_version_count = 1, so the
# iam_set_default_policy_version G2 guard coalesce(policy.policy_version_count, 2) > 1 is UNMET → the
# method SUPPRESSES. Self-attached to fp_setdefaultversion_single_version (so the self-loop guard's
# attached-to-attacker CONTAINS check passes — proving the version-count guard is the SOLE rejection).
resource "aws_iam_policy" "single_ver" {
  name = "${local.prefix}-single-ver"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:GetUser"], Resource = "*" }]
  })
}
resource "aws_iam_user_policy_attachment" "fp_setdefaultversion_single_version" {
  user       = aws_iam_user.attacker["fp_setdefaultversion_single_version"].name
  policy_arn = aws_iam_policy.single_ver.arn
}

# fp_already_admin holds the SAME self-attached customer policy as the iam_create_policy_version
# TP twin (so the self-loop guard's attached-to-attacker CONTAINS check passes) AND
# AdministratorAccess — so set_admin marks it _is_admin and the self-loop's admin-as-source guard
# suppresses. Removing ONLY the admin-as-source guard would let the edge fire (the policy is
# attached and under the version limit), proving the FP is sound.
resource "aws_iam_user_policy_attachment" "fp_already_admin_custom" {
  user       = aws_iam_user.attacker["fp_already_admin"].name
  policy_arn = aws_iam_policy.custom.arn
}
resource "aws_iam_user_policy_attachment" "fp_already_admin_admin" {
  user       = aws_iam_user.attacker["fp_already_admin"].name
  policy_arn = local.admin_policy
}
