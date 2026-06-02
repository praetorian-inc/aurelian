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
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
    }]
  })
  tags = { Purpose = "aurelian-pathfinding-e2e" }
}

resource "aws_iam_role_policy_attachment" "admin_target" {
  role       = aws_iam_role.admin_target.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# -----------------------------------------------------------------------------
# lab_amplify_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_amplify_001" {
  name = "${local.prefix}-lab-amplify-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-amplify-001" }
}
resource "aws_iam_user_policy" "lab_amplify_001" {
  name = "${local.prefix}-lab-amplify-001"
  user = aws_iam_user.lab_amplify_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "amplify:CreateApp", "amplify:CreateBranch", "amplify:StartJob"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_apprunner_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_apprunner_001" {
  name = "${local.prefix}-lab-apprunner-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-apprunner-001" }
}
resource "aws_iam_user_policy" "lab_apprunner_001" {
  name = "${local.prefix}-lab-apprunner-001"
  user = aws_iam_user.lab_apprunner_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "apprunner:CreateService"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_apprunner_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_apprunner_002" {
  name = "${local.prefix}-lab-apprunner-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-apprunner-002" }
}
resource "aws_iam_user_policy" "lab_apprunner_002" {
  name = "${local.prefix}-lab-apprunner-002"
  user = aws_iam_user.lab_apprunner_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["apprunner:UpdateService"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_batch_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_batch_001" {
  name = "${local.prefix}-lab-batch-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-batch-001" }
}
resource "aws_iam_user_policy" "lab_batch_001" {
  name = "${local.prefix}-lab-batch-001"
  user = aws_iam_user.lab_batch_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "batch:RegisterJobDefinition", "batch:SubmitJob"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_batch_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_batch_002" {
  name = "${local.prefix}-lab-batch-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-batch-002" }
}
resource "aws_iam_user_policy" "lab_batch_002" {
  name = "${local.prefix}-lab-batch-002"
  user = aws_iam_user.lab_batch_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["batch:SubmitJob"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_bedrock_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_bedrock_001" {
  name = "${local.prefix}-lab-bedrock-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-bedrock-001" }
}
resource "aws_iam_user_policy" "lab_bedrock_001" {
  name = "${local.prefix}-lab-bedrock-001"
  user = aws_iam_user.lab_bedrock_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "bedrock-agentcore:CreateCodeInterpreter"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_bedrock_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_bedrock_002" {
  name = "${local.prefix}-lab-bedrock-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-bedrock-002" }
}
resource "aws_iam_user_policy" "lab_bedrock_002" {
  name = "${local.prefix}-lab-bedrock-002"
  user = aws_iam_user.lab_bedrock_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["bedrock-agentcore:InvokeSession"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_braket_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_braket_001" {
  name = "${local.prefix}-lab-braket-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-braket-001" }
}
resource "aws_iam_user_policy" "lab_braket_001" {
  name = "${local.prefix}-lab-braket-001"
  user = aws_iam_user.lab_braket_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "braket:CreateJob"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_cloudformation_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_cloudformation_001" {
  name = "${local.prefix}-lab-cloudformation-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-cloudformation-001" }
}
resource "aws_iam_user_policy" "lab_cloudformation_001" {
  name = "${local.prefix}-lab-cloudformation-001"
  user = aws_iam_user.lab_cloudformation_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "cloudformation:CreateStack"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_cloudformation_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_cloudformation_002" {
  name = "${local.prefix}-lab-cloudformation-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-cloudformation-002" }
}
resource "aws_iam_user_policy" "lab_cloudformation_002" {
  name = "${local.prefix}-lab-cloudformation-002"
  user = aws_iam_user.lab_cloudformation_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["cloudformation:UpdateStack"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_cloudformation_003
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_cloudformation_003" {
  name = "${local.prefix}-lab-cloudformation-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-cloudformation-003" }
}
resource "aws_iam_user_policy" "lab_cloudformation_003" {
  name = "${local.prefix}-lab-cloudformation-003"
  user = aws_iam_user.lab_cloudformation_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_cloudformation_004
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_cloudformation_004" {
  name = "${local.prefix}-lab-cloudformation-004"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-cloudformation-004" }
}
resource "aws_iam_user_policy" "lab_cloudformation_004" {
  name = "${local.prefix}-lab-cloudformation-004"
  user = aws_iam_user.lab_cloudformation_004.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "cloudformation:UpdateStackSet"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_cloudformation_005
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_cloudformation_005" {
  name = "${local.prefix}-lab-cloudformation-005"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-cloudformation-005" }
}
resource "aws_iam_user_policy" "lab_cloudformation_005" {
  name = "${local.prefix}-lab-cloudformation-005"
  user = aws_iam_user.lab_cloudformation_005.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_codebuild_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_codebuild_001" {
  name = "${local.prefix}-lab-codebuild-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-codebuild-001" }
}
resource "aws_iam_user_policy" "lab_codebuild_001" {
  name = "${local.prefix}-lab-codebuild-001"
  user = aws_iam_user.lab_codebuild_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_codebuild_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_codebuild_002" {
  name = "${local.prefix}-lab-codebuild-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-codebuild-002" }
}
resource "aws_iam_user_policy" "lab_codebuild_002" {
  name = "${local.prefix}-lab-codebuild-002"
  user = aws_iam_user.lab_codebuild_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["codebuild:StartBuild"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_codebuild_003
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_codebuild_003" {
  name = "${local.prefix}-lab-codebuild-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-codebuild-003" }
}
resource "aws_iam_user_policy" "lab_codebuild_003" {
  name = "${local.prefix}-lab-codebuild-003"
  user = aws_iam_user.lab_codebuild_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["codebuild:StartBuildBatch"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_codebuild_004
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_codebuild_004" {
  name = "${local.prefix}-lab-codebuild-004"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-codebuild-004" }
}
resource "aws_iam_user_policy" "lab_codebuild_004" {
  name = "${local.prefix}-lab-codebuild-004"
  user = aws_iam_user.lab_codebuild_004.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuildBatch"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_codedeploy_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_codedeploy_001" {
  name = "${local.prefix}-lab-codedeploy-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-codedeploy-001" }
}
resource "aws_iam_user_policy" "lab_codedeploy_001" {
  name = "${local.prefix}-lab-codedeploy-001"
  user = aws_iam_user.lab_codedeploy_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["codedeploy:CreateDeployment"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_cognito_identity_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_cognito_identity_001" {
  name = "${local.prefix}-lab-cognito-identity-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-cognito-identity-001" }
}
resource "aws_iam_user_policy" "lab_cognito_identity_001" {
  name = "${local.prefix}-lab-cognito-identity-001"
  user = aws_iam_user.lab_cognito_identity_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "cognito-identity:SetIdentityPoolRoles"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ec2_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ec2_001" {
  name = "${local.prefix}-lab-ec2-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ec2-001" }
}
resource "aws_iam_user_policy" "lab_ec2_001" {
  name = "${local.prefix}-lab-ec2-001"
  user = aws_iam_user.lab_ec2_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ec2:RunInstances"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ec2_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ec2_002" {
  name = "${local.prefix}-lab-ec2-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ec2-002" }
}
resource "aws_iam_user_policy" "lab_ec2_002" {
  name = "${local.prefix}-lab-ec2-002"
  user = aws_iam_user.lab_ec2_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ec2:ModifyInstanceAttribute", "ec2:StopInstances", "ec2:StartInstances"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_ec2_003
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ec2_003" {
  name = "${local.prefix}-lab-ec2-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ec2-003" }
}
resource "aws_iam_user_policy" "lab_ec2_003" {
  name = "${local.prefix}-lab-ec2-003"
  user = aws_iam_user.lab_ec2_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ec2-instance-connect:SendSSHPublicKey"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_ec2_004
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ec2_004" {
  name = "${local.prefix}-lab-ec2-004"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ec2-004" }
}
resource "aws_iam_user_policy" "lab_ec2_004" {
  name = "${local.prefix}-lab-ec2-004"
  user = aws_iam_user.lab_ec2_004.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ec2:RequestSpotInstances"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ec2_005
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ec2_005" {
  name = "${local.prefix}-lab-ec2-005"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ec2-005" }
}
resource "aws_iam_user_policy" "lab_ec2_005" {
  name = "${local.prefix}-lab-ec2-005"
  user = aws_iam_user.lab_ec2_005.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ec2:CreateLaunchTemplateVersion", "ec2:ModifyLaunchTemplate"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_ecs_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ecs_001" {
  name = "${local.prefix}-lab-ecs-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ecs-001" }
}
resource "aws_iam_user_policy" "lab_ecs_001" {
  name = "${local.prefix}-lab-ecs-001"
  user = aws_iam_user.lab_ecs_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:CreateService"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ecs_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ecs_002" {
  name = "${local.prefix}-lab-ecs-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ecs-002" }
}
resource "aws_iam_user_policy" "lab_ecs_002" {
  name = "${local.prefix}-lab-ecs-002"
  user = aws_iam_user.lab_ecs_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:RunTask"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ecs_003
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ecs_003" {
  name = "${local.prefix}-lab-ecs-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ecs-003" }
}
resource "aws_iam_user_policy" "lab_ecs_003" {
  name = "${local.prefix}-lab-ecs-003"
  user = aws_iam_user.lab_ecs_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:CreateService"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ecs_004
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ecs_004" {
  name = "${local.prefix}-lab-ecs-004"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ecs-004" }
}
resource "aws_iam_user_policy" "lab_ecs_004" {
  name = "${local.prefix}-lab-ecs-004"
  user = aws_iam_user.lab_ecs_004.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ecs_005
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ecs_005" {
  name = "${local.prefix}-lab-ecs-005"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ecs-005" }
}
resource "aws_iam_user_policy" "lab_ecs_005" {
  name = "${local.prefix}-lab-ecs-005"
  user = aws_iam_user.lab_ecs_005.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:StartTask"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ecs_006
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ecs_006" {
  name = "${local.prefix}-lab-ecs-006"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ecs-006" }
}
resource "aws_iam_user_policy" "lab_ecs_006" {
  name = "${local.prefix}-lab-ecs-006"
  user = aws_iam_user.lab_ecs_006.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ecs:ExecuteCommand", "ecs:DescribeTasks"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_ecs_007
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ecs_007" {
  name = "${local.prefix}-lab-ecs-007"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ecs-007" }
}
resource "aws_iam_user_policy" "lab_ecs_007" {
  name = "${local.prefix}-lab-ecs-007"
  user = aws_iam_user.lab_ecs_007.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ecs:StartTask", "ecs:RegisterContainerInstance"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ecs_008
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ecs_008" {
  name = "${local.prefix}-lab-ecs-008"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ecs-008" }
}
resource "aws_iam_user_policy" "lab_ecs_008" {
  name = "${local.prefix}-lab-ecs-008"
  user = aws_iam_user.lab_ecs_008.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ecs:RunTask"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ecs_009
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ecs_009" {
  name = "${local.prefix}-lab-ecs-009"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ecs-009" }
}
resource "aws_iam_user_policy" "lab_ecs_009" {
  name = "${local.prefix}-lab-ecs-009"
  user = aws_iam_user.lab_ecs_009.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ecs:StartTask"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_emr_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_emr_001" {
  name = "${local.prefix}-lab-emr-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-emr-001" }
}
resource "aws_iam_user_policy" "lab_emr_001" {
  name = "${local.prefix}-lab-emr-001"
  user = aws_iam_user.lab_emr_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "elasticmapreduce:RunJobFlow"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_emr_serverless_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_emr_serverless_001" {
  name = "${local.prefix}-lab-emr-serverless-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-emr-serverless-001" }
}
resource "aws_iam_user_policy" "lab_emr_serverless_001" {
  name = "${local.prefix}-lab-emr-serverless-001"
  user = aws_iam_user.lab_emr_serverless_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "emr-serverless:CreateApplication", "emr-serverless:StartJobRun"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_gamelift_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_gamelift_001" {
  name = "${local.prefix}-lab-gamelift-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-gamelift-001" }
}
resource "aws_iam_user_policy" "lab_gamelift_001" {
  name = "${local.prefix}-lab-gamelift-001"
  user = aws_iam_user.lab_gamelift_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "gamelift:CreateBuild", "gamelift:CreateFleet"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_glue_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_glue_001" {
  name = "${local.prefix}-lab-glue-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-glue-001" }
}
resource "aws_iam_user_policy" "lab_glue_001" {
  name = "${local.prefix}-lab-glue-001"
  user = aws_iam_user.lab_glue_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "glue:CreateDevEndpoint"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_glue_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_glue_002" {
  name = "${local.prefix}-lab-glue-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-glue-002" }
}
resource "aws_iam_user_policy" "lab_glue_002" {
  name = "${local.prefix}-lab-glue-002"
  user = aws_iam_user.lab_glue_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["glue:UpdateDevEndpoint"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_glue_003
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_glue_003" {
  name = "${local.prefix}-lab-glue-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-glue-003" }
}
resource "aws_iam_user_policy" "lab_glue_003" {
  name = "${local.prefix}-lab-glue-003"
  user = aws_iam_user.lab_glue_003.name
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
# lab_glue_004
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_glue_004" {
  name = "${local.prefix}-lab-glue-004"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-glue-004" }
}
resource "aws_iam_user_policy" "lab_glue_004" {
  name = "${local.prefix}-lab-glue-004"
  user = aws_iam_user.lab_glue_004.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "glue:CreateJob", "glue:CreateTrigger"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_glue_005
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_glue_005" {
  name = "${local.prefix}-lab-glue-005"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-glue-005" }
}
resource "aws_iam_user_policy" "lab_glue_005" {
  name = "${local.prefix}-lab-glue-005"
  user = aws_iam_user.lab_glue_005.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "glue:UpdateJob", "glue:StartJobRun"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_glue_006
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_glue_006" {
  name = "${local.prefix}-lab-glue-006"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-glue-006" }
}
resource "aws_iam_user_policy" "lab_glue_006" {
  name = "${local.prefix}-lab-glue-006"
  user = aws_iam_user.lab_glue_006.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "glue:UpdateJob", "glue:CreateTrigger"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_glue_007
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_glue_007" {
  name = "${local.prefix}-lab-glue-007"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-glue-007" }
}
resource "aws_iam_user_policy" "lab_glue_007" {
  name = "${local.prefix}-lab-glue-007"
  user = aws_iam_user.lab_glue_007.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "glue:CreateSession", "glue:RunStatement"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_001" {
  name = "${local.prefix}-lab-iam-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-001" }
}
resource "aws_iam_user_policy" "lab_iam_001" {
  name = "${local.prefix}-lab-iam-001"
  user = aws_iam_user.lab_iam_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:CreatePolicyVersion"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_002" {
  name = "${local.prefix}-lab-iam-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-002" }
}
resource "aws_iam_user_policy" "lab_iam_002" {
  name = "${local.prefix}-lab-iam-002"
  user = aws_iam_user.lab_iam_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:CreateAccessKey"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_003
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_003" {
  name = "${local.prefix}-lab-iam-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-003" }
}
resource "aws_iam_user_policy" "lab_iam_003" {
  name = "${local.prefix}-lab-iam-003"
  user = aws_iam_user.lab_iam_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:DeleteAccessKey", "iam:CreateAccessKey"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_004
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_004" {
  name = "${local.prefix}-lab-iam-004"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-004" }
}
resource "aws_iam_user_policy" "lab_iam_004" {
  name = "${local.prefix}-lab-iam-004"
  user = aws_iam_user.lab_iam_004.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:CreateLoginProfile"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_005
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_005" {
  name = "${local.prefix}-lab-iam-005"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-005" }
}
resource "aws_iam_user_policy" "lab_iam_005" {
  name = "${local.prefix}-lab-iam-005"
  user = aws_iam_user.lab_iam_005.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:PutRolePolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_006
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_006" {
  name = "${local.prefix}-lab-iam-006"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-006" }
}
resource "aws_iam_user_policy" "lab_iam_006" {
  name = "${local.prefix}-lab-iam-006"
  user = aws_iam_user.lab_iam_006.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:UpdateLoginProfile"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_007
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_007" {
  name = "${local.prefix}-lab-iam-007"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-007" }
}
resource "aws_iam_user_policy" "lab_iam_007" {
  name = "${local.prefix}-lab-iam-007"
  user = aws_iam_user.lab_iam_007.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:PutUserPolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_008
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_008" {
  name = "${local.prefix}-lab-iam-008"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-008" }
}
resource "aws_iam_user_policy" "lab_iam_008" {
  name = "${local.prefix}-lab-iam-008"
  user = aws_iam_user.lab_iam_008.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:AttachUserPolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_009
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_009" {
  name = "${local.prefix}-lab-iam-009"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-009" }
}
resource "aws_iam_user_policy" "lab_iam_009" {
  name = "${local.prefix}-lab-iam-009"
  user = aws_iam_user.lab_iam_009.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:AttachRolePolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_010
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_010" {
  name = "${local.prefix}-lab-iam-010"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-010" }
}
resource "aws_iam_user_policy" "lab_iam_010" {
  name = "${local.prefix}-lab-iam-010"
  user = aws_iam_user.lab_iam_010.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:AttachGroupPolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_011
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_011" {
  name = "${local.prefix}-lab-iam-011"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-011" }
}
resource "aws_iam_user_policy" "lab_iam_011" {
  name = "${local.prefix}-lab-iam-011"
  user = aws_iam_user.lab_iam_011.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:PutGroupPolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_012
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_012" {
  name = "${local.prefix}-lab-iam-012"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-012" }
}
resource "aws_iam_user_policy" "lab_iam_012" {
  name = "${local.prefix}-lab-iam-012"
  user = aws_iam_user.lab_iam_012.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:UpdateAssumeRolePolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_013
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_013" {
  name = "${local.prefix}-lab-iam-013"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-013" }
}
resource "aws_iam_user_policy" "lab_iam_013" {
  name = "${local.prefix}-lab-iam-013"
  user = aws_iam_user.lab_iam_013.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:AddUserToGroup"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_014
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_014" {
  name = "${local.prefix}-lab-iam-014"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-014" }
}
resource "aws_iam_user_policy" "lab_iam_014" {
  name = "${local.prefix}-lab-iam-014"
  user = aws_iam_user.lab_iam_014.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:AttachRolePolicy", "sts:AssumeRole"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_015
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_015" {
  name = "${local.prefix}-lab-iam-015"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-015" }
}
resource "aws_iam_user_policy" "lab_iam_015" {
  name = "${local.prefix}-lab-iam-015"
  user = aws_iam_user.lab_iam_015.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:AttachUserPolicy", "iam:CreateAccessKey"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_016
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_016" {
  name = "${local.prefix}-lab-iam-016"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-016" }
}
resource "aws_iam_user_policy" "lab_iam_016" {
  name = "${local.prefix}-lab-iam-016"
  user = aws_iam_user.lab_iam_016.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:CreatePolicyVersion", "sts:AssumeRole"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_017
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_017" {
  name = "${local.prefix}-lab-iam-017"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-017" }
}
resource "aws_iam_user_policy" "lab_iam_017" {
  name = "${local.prefix}-lab-iam-017"
  user = aws_iam_user.lab_iam_017.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:PutRolePolicy", "sts:AssumeRole"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_018
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_018" {
  name = "${local.prefix}-lab-iam-018"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-018" }
}
resource "aws_iam_user_policy" "lab_iam_018" {
  name = "${local.prefix}-lab-iam-018"
  user = aws_iam_user.lab_iam_018.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:PutUserPolicy", "iam:CreateAccessKey"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_019
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_019" {
  name = "${local.prefix}-lab-iam-019"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-019" }
}
resource "aws_iam_user_policy" "lab_iam_019" {
  name = "${local.prefix}-lab-iam-019"
  user = aws_iam_user.lab_iam_019.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_020
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_020" {
  name = "${local.prefix}-lab-iam-020"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-020" }
}
resource "aws_iam_user_policy" "lab_iam_020" {
  name = "${local.prefix}-lab-iam-020"
  user = aws_iam_user.lab_iam_020.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:CreatePolicyVersion", "iam:UpdateAssumeRolePolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_iam_021
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_iam_021" {
  name = "${local.prefix}-lab-iam-021"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-iam-021" }
}
resource "aws_iam_user_policy" "lab_iam_021" {
  name = "${local.prefix}-lab-iam-021"
  user = aws_iam_user.lab_iam_021.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_imagebuilder_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_imagebuilder_001" {
  name = "${local.prefix}-lab-imagebuilder-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-imagebuilder-001" }
}
resource "aws_iam_user_policy" "lab_imagebuilder_001" {
  name = "${local.prefix}-lab-imagebuilder-001"
  user = aws_iam_user.lab_imagebuilder_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "imagebuilder:CreateInfrastructureConfiguration", "imagebuilder:CreateComponent", "imagebuilder:CreateImageRecipe", "imagebuilder:CreateImage"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_kinesisanalytics_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_kinesisanalytics_001" {
  name = "${local.prefix}-lab-kinesisanalytics-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-kinesisanalytics-001" }
}
resource "aws_iam_user_policy" "lab_kinesisanalytics_001" {
  name = "${local.prefix}-lab-kinesisanalytics-001"
  user = aws_iam_user.lab_kinesisanalytics_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "kinesisanalytics:CreateApplication", "kinesisanalytics:StartApplication"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_lambda_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_lambda_001" {
  name = "${local.prefix}-lab-lambda-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-lambda-001" }
}
resource "aws_iam_user_policy" "lab_lambda_001" {
  name = "${local.prefix}-lab-lambda-001"
  user = aws_iam_user.lab_lambda_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_lambda_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_lambda_002" {
  name = "${local.prefix}-lab-lambda-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-lambda-002" }
}
resource "aws_iam_user_policy" "lab_lambda_002" {
  name = "${local.prefix}-lab-lambda-002"
  user = aws_iam_user.lab_lambda_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_lambda_003
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_lambda_003" {
  name = "${local.prefix}-lab-lambda-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-lambda-003" }
}
resource "aws_iam_user_policy" "lab_lambda_003" {
  name = "${local.prefix}-lab-lambda-003"
  user = aws_iam_user.lab_lambda_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:UpdateFunctionCode"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_lambda_004
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_lambda_004" {
  name = "${local.prefix}-lab-lambda-004"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-lambda-004" }
}
resource "aws_iam_user_policy" "lab_lambda_004" {
  name = "${local.prefix}-lab-lambda-004"
  user = aws_iam_user.lab_lambda_004.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_lambda_005
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_lambda_005" {
  name = "${local.prefix}-lab-lambda-005"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-lambda-005" }
}
resource "aws_iam_user_policy" "lab_lambda_005" {
  name = "${local.prefix}-lab-lambda-005"
  user = aws_iam_user.lab_lambda_005.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:UpdateFunctionCode", "lambda:AddPermission"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_lambda_006
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_lambda_006" {
  name = "${local.prefix}-lab-lambda-006"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-lambda-006" }
}
resource "aws_iam_user_policy" "lab_lambda_006" {
  name = "${local.prefix}-lab-lambda-006"
  user = aws_iam_user.lab_lambda_006.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "lambda:CreateFunction", "lambda:AddPermission"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_omics_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_omics_001" {
  name = "${local.prefix}-lab-omics-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-omics-001" }
}
resource "aws_iam_user_policy" "lab_omics_001" {
  name = "${local.prefix}-lab-omics-001"
  user = aws_iam_user.lab_omics_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "omics:CreateWorkflow", "omics:StartRun"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_sagemaker_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_sagemaker_001" {
  name = "${local.prefix}-lab-sagemaker-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-sagemaker-001" }
}
resource "aws_iam_user_policy" "lab_sagemaker_001" {
  name = "${local.prefix}-lab-sagemaker-001"
  user = aws_iam_user.lab_sagemaker_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "sagemaker:CreateNotebookInstance"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_sagemaker_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_sagemaker_002" {
  name = "${local.prefix}-lab-sagemaker-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-sagemaker-002" }
}
resource "aws_iam_user_policy" "lab_sagemaker_002" {
  name = "${local.prefix}-lab-sagemaker-002"
  user = aws_iam_user.lab_sagemaker_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "sagemaker:CreateTrainingJob"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_sagemaker_003
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_sagemaker_003" {
  name = "${local.prefix}-lab-sagemaker-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-sagemaker-003" }
}
resource "aws_iam_user_policy" "lab_sagemaker_003" {
  name = "${local.prefix}-lab-sagemaker-003"
  user = aws_iam_user.lab_sagemaker_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "sagemaker:CreateProcessingJob"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_sagemaker_004
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_sagemaker_004" {
  name = "${local.prefix}-lab-sagemaker-004"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-sagemaker-004" }
}
resource "aws_iam_user_policy" "lab_sagemaker_004" {
  name = "${local.prefix}-lab-sagemaker-004"
  user = aws_iam_user.lab_sagemaker_004.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["sagemaker:CreatePresignedNotebookInstanceUrl"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_sagemaker_005
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_sagemaker_005" {
  name = "${local.prefix}-lab-sagemaker-005"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-sagemaker-005" }
}
resource "aws_iam_user_policy" "lab_sagemaker_005" {
  name = "${local.prefix}-lab-sagemaker-005"
  user = aws_iam_user.lab_sagemaker_005.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["sagemaker:UpdateNotebookInstanceLifecycleConfig"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_scheduler_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_scheduler_001" {
  name = "${local.prefix}-lab-scheduler-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-scheduler-001" }
}
resource "aws_iam_user_policy" "lab_scheduler_001" {
  name = "${local.prefix}-lab-scheduler-001"
  user = aws_iam_user.lab_scheduler_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "scheduler:CreateSchedule"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_ssm_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ssm_001" {
  name = "${local.prefix}-lab-ssm-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ssm-001" }
}
resource "aws_iam_user_policy" "lab_ssm_001" {
  name = "${local.prefix}-lab-ssm-001"
  user = aws_iam_user.lab_ssm_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ssm:StartSession"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_ssm_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ssm_002" {
  name = "${local.prefix}-lab-ssm-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ssm-002" }
}
resource "aws_iam_user_policy" "lab_ssm_002" {
  name = "${local.prefix}-lab-ssm-002"
  user = aws_iam_user.lab_ssm_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ssm:SendCommand"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_ssm_003
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_ssm_003" {
  name = "${local.prefix}-lab-ssm-003"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-ssm-003" }
}
resource "aws_iam_user_policy" "lab_ssm_003" {
  name = "${local.prefix}-lab-ssm-003"
  user = aws_iam_user.lab_ssm_003.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ssm:CreateDocument", "ssm:StartAutomationExecution"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_stepfunctions_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_stepfunctions_001" {
  name = "${local.prefix}-lab-stepfunctions-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-stepfunctions-001" }
}
resource "aws_iam_user_policy" "lab_stepfunctions_001" {
  name = "${local.prefix}-lab-stepfunctions-001"
  user = aws_iam_user.lab_stepfunctions_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "states:CreateStateMachine", "states:StartExecution"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# lab_stepfunctions_002
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_stepfunctions_002" {
  name = "${local.prefix}-lab-stepfunctions-002"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-stepfunctions-002" }
}
resource "aws_iam_user_policy" "lab_stepfunctions_002" {
  name = "${local.prefix}-lab-stepfunctions-002"
  user = aws_iam_user.lab_stepfunctions_002.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["states:UpdateStateMachine", "states:StartExecution"], Resource = "*" }]
  })
}

# -----------------------------------------------------------------------------
# lab_sts_001
# -----------------------------------------------------------------------------
resource "aws_iam_user" "lab_sts_001" {
  name = "${local.prefix}-lab-sts-001"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "lab-sts-001" }
}
resource "aws_iam_user_policy" "lab_sts_001" {
  name = "${local.prefix}-lab-sts-001"
  user = aws_iam_user.lab_sts_001.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["sts:AssumeRole"], Resource = "*" }]
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

# FP: lambda:UpdateFunctionCode only → method_39 (UpdateCode+Invoke) must NOT fire
resource "aws_iam_user" "fp_lambda_004_no_invoke" {
  name = "${local.prefix}-fp-lambda-004-noinv"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-lambda-004-no-invoke" }
}
resource "aws_iam_user_policy" "fp_lambda_004_no_invoke" {
  name = "${local.prefix}-fp-lambda-004-noinv"
  user = aws_iam_user.fp_lambda_004_no_invoke.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:UpdateFunctionCode"], Resource = "*" }]
  })
}

# FP: lambda:UpdateFunctionCode only → method_65 (UpdateCode+AddPermission) must NOT fire
resource "aws_iam_user" "fp_lambda_005_no_addpermission" {
  name = "${local.prefix}-fp-lambda-005-noadd"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-lambda-005-no-addpermission" }
}
resource "aws_iam_user_policy" "fp_lambda_005_no_addpermission" {
  name = "${local.prefix}-fp-lambda-005-noadd"
  user = aws_iam_user.fp_lambda_005_no_addpermission.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:UpdateFunctionCode"], Resource = "*" }]
  })
}

# FP: iam:PassRole only → method_60 (PassRole+CreateDevEndpoint) must NOT fire
resource "aws_iam_user" "fp_glue_001_no_createdevendpoint" {
  name = "${local.prefix}-fp-glue-001-nodev"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-glue-001-no-createdevendpoint" }
}
resource "aws_iam_user_policy" "fp_glue_001_no_createdevendpoint" {
  name = "${local.prefix}-fp-glue-001-nodev"
  user = aws_iam_user.fp_glue_001_no_createdevendpoint.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:PassRole"], Resource = aws_iam_role.admin_target.arn }]
  })
}

# FP: ecs:RunTask only (no PassRole) → method_32 must NOT fire
resource "aws_iam_user" "fp_ecs_runtask_no_passrole" {
  name = "${local.prefix}-fp-ecs-run-nopr"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-ecs-runtask-no-passrole" }
}
resource "aws_iam_user_policy" "fp_ecs_runtask_no_passrole" {
  name = "${local.prefix}-fp-ecs-run-nopr"
  user = aws_iam_user.fp_ecs_runtask_no_passrole.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ecs:RunTask"], Resource = "*" }]
  })
}

# FP: elasticmapreduce:RunJobFlow only (no PassRole) → method_57 must NOT fire
resource "aws_iam_user" "fp_emr_runjobflow_no_passrole" {
  name = "${local.prefix}-fp-emr-run-nopr"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-emr-runjobflow-no-passrole" }
}
resource "aws_iam_user_policy" "fp_emr_runjobflow_no_passrole" {
  name = "${local.prefix}-fp-emr-run-nopr"
  user = aws_iam_user.fp_emr_runjobflow_no_passrole.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["elasticmapreduce:RunJobFlow"], Resource = "*" }]
  })
}

# FP: PassRole + RegisterJobDefinition (no SubmitJob) → method_45 compound partial check
resource "aws_iam_user" "fp_batch_001_no_submitjob" {
  name = "${local.prefix}-fp-batch-001-nosubmit"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-batch-001-no-submitjob" }
}
resource "aws_iam_user_policy" "fp_batch_001_no_submitjob" {
  name = "${local.prefix}-fp-batch-001-nosubmit"
  user = aws_iam_user.fp_batch_001_no_submitjob.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "batch:RegisterJobDefinition"]
      Resource = "*"
    }]
  })
}

# FP: ssm:StartAutomationExecution only → method_84 (CreateDoc+StartAutomation) must NOT fire
resource "aws_iam_user" "fp_ssm_startautomation_only" {
  name = "${local.prefix}-fp-ssm-startauto-only"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-ssm-startautomation-only" }
}
resource "aws_iam_user_policy" "fp_ssm_startautomation_only" {
  name = "${local.prefix}-fp-ssm-startauto-only"
  user = aws_iam_user.fp_ssm_startautomation_only.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ssm:StartAutomationExecution"], Resource = "*" }]
  })
}

# FP: states:UpdateStateMachine only → method_71 (UpdateStateMachine+StartExecution) must NOT fire
resource "aws_iam_user" "fp_sfn_updatestatemachine_only" {
  name = "${local.prefix}-fp-sfn-updatesm-only"
  tags = { Purpose = "aurelian-pathfinding-e2e", Lab = "fp-sfn-updatestatemachine-only" }
}
resource "aws_iam_user_policy" "fp_sfn_updatestatemachine_only" {
  name = "${local.prefix}-fp-sfn-updatesm-only"
  user = aws_iam_user.fp_sfn_updatestatemachine_only.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["states:UpdateStateMachine"], Resource = "*" }]
  })
}
data "aws_caller_identity" "current" {}
