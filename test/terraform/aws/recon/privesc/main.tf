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
  prefix = "aur-privesc-${random_id.run.hex}"
}

# -----------------------------------------------------------------------------
# IAM Role that can be passed (shared PassRole target across all methods)
# -----------------------------------------------------------------------------
resource "aws_iam_role" "passable" {
  name = "${local.prefix}-passable-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_iam_role_policy_attachment" "passable_admin" {
  role       = aws_iam_role.passable.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# -----------------------------------------------------------------------------
# User with existing IAM privesc permissions (methods 01–22, regression baseline)
# -----------------------------------------------------------------------------
resource "aws_iam_user" "iam_privesc" {
  name = "${local.prefix}-iam-privesc-user"
  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_iam_user_policy" "iam_privesc" {
  name = "${local.prefix}-iam-privesc-policy"
  user = aws_iam_user.iam_privesc.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IamPrivescMethods01to13"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:CreateAccessKey",
          "iam:CreateLoginProfile",
          "iam:UpdateLoginProfile",
          "iam:AttachUserPolicy",
          "iam:AttachGroupPolicy",
          "iam:AttachRolePolicy",
          "iam:PutUserPolicy",
          "iam:PutGroupPolicy",
          "iam:PutRolePolicy",
          "iam:AddUserToGroup",
          "iam:UpdateAssumeRolePolicy",
        ]
        Resource = "*"
      },
      {
        Sid    = "StsAndLambdaMethods"
        Effect = "Allow"
        Action = [
          "sts:AssumeRole",
          "iam:PassRole",
          "lambda:CreateFunction",
          "lambda:UpdateFunctionCode",
          "lambda:InvokeFunction",
          "lambda:CreateEventSourceMapping",
          "lambda:AddPermission",
        ]
        Resource = "*"
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# User with PassRole + new service permissions (methods 43–72)
# -----------------------------------------------------------------------------
resource "aws_iam_user" "new_services" {
  name = "${local.prefix}-new-services-user"
  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_iam_user_policy" "new_services_passrole" {
  name = "${local.prefix}-new-services-passrole"
  user = aws_iam_user.new_services.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PassRole"
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = aws_iam_role.passable.arn
      },
      {
        Sid    = "NewServiceCreation"
        Effect = "Allow"
        Action = [
          # method_43: App Runner CreateService
          "apprunner:CreateService",
          # method_45: Batch RegisterJobDefinition
          "batch:RegisterJobDefinition",
          # method_47: Braket CreateJob
          "braket:CreateJob",
          # method_48: CloudFormation CreateStackSet
          "cloudformation:CreateStackSet",
          # method_49: CloudFormation UpdateStackSet
          "cloudformation:UpdateStackSet",
          # method_51: Cognito SetIdentityPoolRoles
          "cognito-identity:SetIdentityPoolRoles",
          # method_54: ECS CreateService
          "ecs:CreateService",
          # method_55: ECS StartTask
          "ecs:StartTask",
          # method_57: EMR RunJobFlow
          "elasticmapreduce:RunJobFlow",
          # method_58: EMR Serverless CreateApplication
          "emr-serverless:CreateApplication",
          # method_59: GameLift CreateFleet
          "gamelift:CreateFleet",
          # method_60: Glue CreateDevEndpoint
          "glue:CreateDevEndpoint",
          # method_61: Glue UpdateJob
          "glue:UpdateJob",
          # method_62: Glue CreateSession
          "glue:CreateSession",
          # method_63: Image Builder CreateInfrastructureConfiguration
          "imagebuilder:CreateInfrastructureConfiguration",
          # method_64: Kinesis Analytics CreateApplication
          "kinesisanalytics:CreateApplication",
          # method_66: HealthOmics CreateWorkflow
          "omics:CreateWorkflow",
          # method_68: EventBridge Scheduler CreateSchedule
          "scheduler:CreateSchedule",
          # method_69: SSM StartAutomationExecution
          "ssm:StartAutomationExecution",
          # method_70: Step Functions CreateStateMachine
          "states:CreateStateMachine",
          # method_71: Step Functions UpdateStateMachine
          "states:UpdateStateMachine",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_user_policy" "new_services_standalone" {
  name = "${local.prefix}-new-services-standalone"
  user = aws_iam_user.new_services.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StandaloneNewMethods"
        Effect = "Allow"
        Action = [
          # method_44: App Runner UpdateService
          "apprunner:UpdateService",
          # method_46: Batch SubmitJob
          "batch:SubmitJob",
          # method_50: CodeDeploy CreateDeployment
          "codedeploy:CreateDeployment",
          # method_52: EC2 Instance Connect SendSSHPublicKey
          "ec2-instance-connect:SendSSHPublicKey",
          # method_53: EC2 ReplaceIamInstanceProfileAssociation
          "ec2:ReplaceIamInstanceProfileAssociation",
          # method_56: ECS ExecuteCommand
          "ecs:ExecuteCommand",
          # method_65: Lambda UpdateFunctionCode + AddPermission (both required)
          "lambda:UpdateFunctionCode",
          "lambda:AddPermission",
          # method_67: SageMaker UpdateNotebookInstanceLifecycleConfig
          "sagemaker:UpdateNotebookInstanceLifecycleConfig",
          # method_72: Bedrock AgentCore InvokeSession
          "bedrock-agentcore:InvokeSession",
        ]
        Resource = "*"
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# Existing method coverage: SSM, CodeBuild, ECS RunTask, SageMaker, Glue, Bedrock
# -----------------------------------------------------------------------------
resource "aws_iam_user" "extended_services" {
  name = "${local.prefix}-extended-services-user"
  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_iam_user_policy" "extended_services" {
  name = "${local.prefix}-extended-services-policy"
  user = aws_iam_user.extended_services.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PassRole"
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = aws_iam_role.passable.arn
      },
      {
        Sid    = "ExtendedServiceMethods"
        Effect = "Allow"
        Action = [
          # method_23/24/25: SSM
          "ssm:SendCommand",
          "ssm:StartSession",
          "ssm:CreateAssociation",
          # method_27/33/34: CodeBuild
          "codebuild:CreateProject",
          "codebuild:StartBuild",
          "codebuild:StartBuildBatch",
          "codebuild:UpdateProject",
          # method_32: ECS RunTask
          "ecs:RunTask",
          # method_35/36/37: SageMaker
          "sagemaker:CreatePresignedNotebookInstanceUrl",
          "sagemaker:CreateTrainingJob",
          "sagemaker:CreateProcessingJob",
          # method_29: Glue UpdateDevEndpoint
          "glue:UpdateDevEndpoint",
          # method_38: AutoScaling LaunchTemplate
          "ec2:CreateLaunchTemplate",
          "autoscaling:CreateAutoScalingGroup",
          # method_40: Bedrock CreateCodeInterpreter
          "bedrock-agentcore:CreateCodeInterpreter",
        ]
        Resource = "*"
      },
    ]
  })
}
