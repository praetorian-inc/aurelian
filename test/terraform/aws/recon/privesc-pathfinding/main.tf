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
