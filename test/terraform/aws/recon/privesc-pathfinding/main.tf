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

locals {
  prefix = "aur-pf-${random_id.run.hex}"
}

# =============================================================================
# Pathfinding.cloud-style attacker IAM users — one per lab technique.
# Each user has EXACTLY the permissions required for one privesc path,
# mirroring the attacker principals deployed by pathfinding.cloud labs.
# This enables per-method true-positive AND false-positive E2E validation.
# =============================================================================

# Shared admin role (the escalation target for all PassRole methods)
resource "aws_iam_role" "admin_target" {
  name = "${local.prefix}-admin-target"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = { Purpose = "aurelian-pathfinding-e2e" }
}

resource "aws_iam_role_policy_attachment" "admin_target" {
  role       = aws_iam_role.admin_target.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# -----------------------------------------------------------------------------
# IAM self-escalation labs (iam-001..013) — standalone single permissions
# Pathfinding.cloud: iam-001-iam-createpolicyversion, iam-002-iam-createaccesskey, etc.
# -----------------------------------------------------------------------------
resource "aws_iam_user" "iam_001" {
  name = "${local.prefix}-iam-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "iam-001" }
}
resource "aws_iam_user_policy" "iam_001" {
  name = "${local.prefix}-iam-001"
  user = aws_iam_user.iam_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:CreatePolicyVersion"], Resource = "*" }]
  })
}

resource "aws_iam_user" "iam_002" {
  name = "${local.prefix}-iam-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "iam-002" }
}
resource "aws_iam_user_policy" "iam_002" {
  name = "${local.prefix}-iam-002"
  user = aws_iam_user.iam_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:CreateAccessKey"], Resource = "*" }]
  })
}

resource "aws_iam_user" "iam_004" {
  name = "${local.prefix}-iam-004"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "iam-004" }
}
resource "aws_iam_user_policy" "iam_004" {
  name = "${local.prefix}-iam-004"
  user = aws_iam_user.iam_004.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:CreateLoginProfile"], Resource = "*" }]
  })
}

resource "aws_iam_user" "iam_006" {
  name = "${local.prefix}-iam-006"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "iam-006" }
}
resource "aws_iam_user_policy" "iam_006" {
  name = "${local.prefix}-iam-006"
  user = aws_iam_user.iam_006.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:UpdateLoginProfile"], Resource = "*" }]
  })
}

resource "aws_iam_user" "iam_012" {
  name = "${local.prefix}-iam-012"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "iam-012" }
}
resource "aws_iam_user_policy" "iam_012" {
  name = "${local.prefix}-iam-012"
  user = aws_iam_user.iam_012.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:UpdateAssumeRolePolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# Lambda privesc labs (lambda-001..006)
# Pathfinding.cloud: lambda-001-iam-passrole+lambda-createfunction+lambda-invokefunction
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lambda_001" {
  name = "${local.prefix}-lambda-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lambda-001" }
}
resource "aws_iam_user_policy" "lambda_001" {
  name = "${local.prefix}-lambda-001"
  user = aws_iam_user.lambda_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_user" "lambda_003" {
  name = "${local.prefix}-lambda-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lambda-003" }
}
resource "aws_iam_user_policy" "lambda_003" {
  name = "${local.prefix}-lambda-003"
  user = aws_iam_user.lambda_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:UpdateFunctionCode"], Resource = "*" }]
  })
}

# False-positive user: has lambda:UpdateFunctionCode but NOT lambda:InvokeFunction
# method_39 (UpdateFunctionCode+InvokeFunction) must NOT fire for this user.
resource "aws_iam_user" "lambda_fp_no_invoke" {
  name = "${local.prefix}-lambda-fp-noinvoke"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lambda-003-fp" }
}
resource "aws_iam_user_policy" "lambda_fp_no_invoke" {
  name = "${local.prefix}-lambda-fp-noinvoke"
  user = aws_iam_user.lambda_fp_no_invoke.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:UpdateFunctionCode"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# Glue privesc labs (glue-001..007)
# Pathfinding.cloud: glue-002-glue-updatedevendpoint
# -----------------------------------------------------------------------------
resource "aws_iam_user" "glue_002" {
  name = "${local.prefix}-glue-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "glue-002" }
}
resource "aws_iam_user_policy" "glue_002" {
  name = "${local.prefix}-glue-002"
  user = aws_iam_user.glue_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["glue:UpdateDevEndpoint"], Resource = "*" }]
  })
}

resource "aws_iam_user" "glue_003" {
  name = "${local.prefix}-glue-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "glue-003" }
}
resource "aws_iam_user_policy" "glue_003" {
  name = "${local.prefix}-glue-003"
  user = aws_iam_user.glue_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "glue:CreateJob", "glue:StartJobRun"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# EC2 privesc labs
# Pathfinding.cloud: ec2-001, ec2-003, ec2-004, ec2-005
# -----------------------------------------------------------------------------
resource "aws_iam_user" "ec2_001" {
  name = "${local.prefix}-ec2-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "ec2-001" }
}
resource "aws_iam_user_policy" "ec2_001" {
  name = "${local.prefix}-ec2-001"
  user = aws_iam_user.ec2_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ec2:RunInstances"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_user" "ec2_003" {
  name = "${local.prefix}-ec2-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "ec2-003" }
}
resource "aws_iam_user_policy" "ec2_003" {
  name = "${local.prefix}-ec2-003"
  user = aws_iam_user.ec2_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ec2-instance-connect:SendSSHPublicKey"], Resource = "*" }]
  })
}

resource "aws_iam_user" "ec2_004" {
  name = "${local.prefix}-ec2-004"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "ec2-004" }
}
resource "aws_iam_user_policy" "ec2_004" {
  name = "${local.prefix}-ec2-004"
  user = aws_iam_user.ec2_004.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ec2:RequestSpotInstances"]
      Resource = "*"
    }]
  })
}

# =============================================================================
# FALSE POSITIVE users — each has only ONE of the two required permissions.
# Methods that need N permissions must NOT fire with N-1 permissions.
# =============================================================================

# FP: PassRole alone (no service action) → no PassRole+service method should fire
resource "aws_iam_user" "fp_passrole_only" {
  name = "${local.prefix}-fp-passrole-only"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-passrole-only" }
}
resource "aws_iam_user_policy" "fp_passrole_only" {
  name = "${local.prefix}-fp-passrole-only"
  user = aws_iam_user.fp_passrole_only.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:PassRole"], Resource = aws_iam_role.admin_target.arn }]
  })
}

# FP: CreateFunction alone (no PassRole, no InvokeFunction) → method_14 must NOT fire
resource "aws_iam_user" "fp_lambda_createfunction_only" {
  name = "${local.prefix}-fp-lambda-cf-only"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-lambda-createfunction-only" }
}
resource "aws_iam_user_policy" "fp_lambda_createfunction_only" {
  name = "${local.prefix}-fp-lambda-cf-only"
  user = aws_iam_user.fp_lambda_createfunction_only.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:CreateFunction"], Resource = "*" }]
  })
}

# FP: InvokeFunction alone (no PassRole, no CreateFunction) → method_14 must NOT fire
resource "aws_iam_user" "fp_lambda_invoke_only" {
  name = "${local.prefix}-fp-lambda-inv-only"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-lambda-invoke-only" }
}
resource "aws_iam_user_policy" "fp_lambda_invoke_only" {
  name = "${local.prefix}-fp-lambda-inv-only"
  user = aws_iam_user.fp_lambda_invoke_only.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = "*" }]
  })
}

# FP: RunInstances alone (no PassRole) → method_15 must NOT fire
resource "aws_iam_user" "fp_ec2_runinstances_only" {
  name = "${local.prefix}-fp-ec2-run-only"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-ec2-runinstances-only" }
}
resource "aws_iam_user_policy" "fp_ec2_runinstances_only" {
  name = "${local.prefix}-fp-ec2-run-only"
  user = aws_iam_user.fp_ec2_runinstances_only.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ec2:RunInstances"], Resource = "*" }]
  })
}

# FP: CreateStack alone (no PassRole) → method_16 (PassRole+CreateStack) must NOT fire
resource "aws_iam_user" "fp_cfn_createstack_only" {
  name = "${local.prefix}-fp-cfn-cs-only"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-cfn-createstack-only" }
}
resource "aws_iam_user_policy" "fp_cfn_createstack_only" {
  name = "${local.prefix}-fp-cfn-cs-only"
  user = aws_iam_user.fp_cfn_createstack_only.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["cloudformation:CreateStack"], Resource = "*" }]
  })
}

# FP: CreateJob alone (no PassRole, no StartJobRun) → method_80 must NOT fire
resource "aws_iam_user" "fp_glue_createjob_only" {
  name = "${local.prefix}-fp-glue-cj-only"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-glue-createjob-only" }
}
resource "aws_iam_user_policy" "fp_glue_createjob_only" {
  name = "${local.prefix}-fp-glue-cj-only"
  user = aws_iam_user.fp_glue_createjob_only.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["glue:CreateJob"], Resource = "*" }]
  })
}

# FP: PassRole + CreateJob (no StartJobRun) → method_80 must NOT fire (needs all 3)
resource "aws_iam_user" "fp_glue_passrole_createjob_nostartjobrun" {
  name = "${local.prefix}-fp-glue-no-sjr"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-glue-passrole-createjob-nostartjobrun" }
}
resource "aws_iam_user_policy" "fp_glue_passrole_createjob_nostartjobrun" {
  name = "${local.prefix}-fp-glue-no-sjr"
  user = aws_iam_user.fp_glue_passrole_createjob_nostartjobrun.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "glue:CreateJob"]
      Resource = "*"
    }]
  })
}

# FP: PassRole + CreateStateMachine (no StartExecution) → method_83 must NOT fire
resource "aws_iam_user" "fp_sfn_no_startexecution" {
  name = "${local.prefix}-fp-sfn-no-start"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-sfn-no-startexecution" }
}
resource "aws_iam_user_policy" "fp_sfn_no_startexecution" {
  name = "${local.prefix}-fp-sfn-no-start"
  user = aws_iam_user.fp_sfn_no_startexecution.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "states:CreateStateMachine"]
      Resource = "*"
    }]
  })
}

# FP: ECS CreateService alone (no PassRole) → method_54 must NOT fire
resource "aws_iam_user" "fp_ecs_createservice_only" {
  name = "${local.prefix}-fp-ecs-cs-only"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-ecs-createservice-only" }
}
resource "aws_iam_user_policy" "fp_ecs_createservice_only" {
  name = "${local.prefix}-fp-ecs-cs-only"
  user = aws_iam_user.fp_ecs_createservice_only.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ecs:CreateService"], Resource = "*" }]
  })
}

# FP: PassRole + CreateApplication (no StartJobRun) → method_85 must NOT fire
resource "aws_iam_user" "fp_emr_serverless_no_startjobrun" {
  name = "${local.prefix}-fp-emrs-no-sjr"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-emrs-no-startjobrun" }
}
resource "aws_iam_user_policy" "fp_emr_serverless_no_startjobrun" {
  name = "${local.prefix}-fp-emrs-no-sjr"
  user = aws_iam_user.fp_emr_serverless_no_startjobrun.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "emr-serverless:CreateApplication"]
      Resource = "*"
    }]
  })
}

# FP: SSM CreateDocument alone (no StartAutomationExecution) → method_84 must NOT fire
resource "aws_iam_user" "fp_ssm_createdoc_only" {
  name = "${local.prefix}-fp-ssm-cd-only"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-ssm-createdocument-only" }
}
resource "aws_iam_user_policy" "fp_ssm_createdoc_only" {
  name = "${local.prefix}-fp-ssm-cd-only"
  user = aws_iam_user.fp_ssm_createdoc_only.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ssm:CreateDocument"], Resource = "*" }]
  })
}
