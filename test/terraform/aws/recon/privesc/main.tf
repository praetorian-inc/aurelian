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
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = {
        Service = [
          "lambda.amazonaws.com",
          "ecs-tasks.amazonaws.com",
          "states.amazonaws.com",
          "glue.amazonaws.com",
          "ec2.amazonaws.com",
          "batch.amazonaws.com",
          "apprunner.amazonaws.com",
          "imagebuilder.amazonaws.com",
          "sagemaker.amazonaws.com",
          "braket.amazonaws.com",
          "emr-serverless.amazonaws.com",
          "scheduler.amazonaws.com",
          "ssm.amazonaws.com",
          "omics.amazonaws.com",
          "kinesisanalytics.amazonaws.com",
        ]
      }
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
          # method_69: SSM StartAutomationExecution (also in extended_services_exec for method_84)
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
          # method_54: ECS CreateService
          "ecs:CreateService",
          # method_61: Glue UpdateJob
          "glue:UpdateJob",
          # method_70/71: Step Functions
          "states:CreateStateMachine",
          "states:UpdateStateMachine",
          # method_68: EventBridge Scheduler
          "scheduler:CreateSchedule",
          # method_45/46: Batch
          "batch:RegisterJobDefinition",
          "batch:SubmitJob",
          # method_63: Image Builder
          "imagebuilder:CreateInfrastructureConfiguration",
          # method_67: SageMaker lifecycle config
          "sagemaker:UpdateNotebookInstanceLifecycleConfig",
          # method_51: Cognito
          "cognito-identity:SetIdentityPoolRoles",
        ]
        Resource = "*"
      },
    ]
  })
}

# Compound execution methods — the creation action is in extended_services above;
# these are the matching execute/run/start actions required to complete the attack path.
resource "aws_iam_user_policy" "extended_services_exec" {
  name = "${local.prefix}-extended-services-exec"
  user = aws_iam_user.extended_services.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "CompoundExecMethods"
      Effect = "Allow"
      Action = [
        # method_80: glue:CreateJob + StartJobRun
        "glue:CreateJob",
        "glue:StartJobRun",
        # method_82: glue:CreateSession + RunStatement
        "glue:RunStatement",
        # method_77/78: CreateTrigger (paired with CreateJob/UpdateJob)
        "glue:CreateTrigger",
        # method_83: states:StartExecution (paired with CreateStateMachine)
        "states:StartExecution",
        # method_84: ssm:CreateDocument + StartAutomationExecution (both on same user)
        "ssm:CreateDocument",
        "ssm:StartAutomationExecution",
        # method_85: emr-serverless:StartJobRun (paired with CreateApplication)
        "emr-serverless:StartJobRun",
        # method_86: kinesisanalytics:StartApplication (paired with CreateApplication)
        "kinesisanalytics:StartApplication",
        # method_87: omics:StartRun (paired with CreateWorkflow)
        "omics:StartRun",
        # method_88: gamelift:CreateBuild (paired with CreateFleet)
        "gamelift:CreateBuild",
        # method_89: imagebuilder:CreateImage (paired with CreateInfrastructureConfiguration)
        "imagebuilder:CreateComponent",
        "imagebuilder:CreateImageRecipe",
        "imagebuilder:CreateImage",
      ]
      Resource = "*"
    }]
  })
}

# New compound and standalone methods (73-79) for new_services user
resource "aws_iam_user_policy" "new_services_compound" {
  name = "${local.prefix}-new-services-compound"
  user = aws_iam_user.new_services.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "CompoundAndStandaloneNewMethods"
      Effect = "Allow"
      Action = [
        # method_73: ec2:RequestSpotInstances (distinct from RunInstances)
        "ec2:RequestSpotInstances",
        # method_74: CreateLaunchTemplateVersion + ModifyLaunchTemplate
        "ec2:CreateLaunchTemplateVersion",
        "ec2:ModifyLaunchTemplate",
        # method_75: Amplify CreateApp + CreateBranch + StartJob
        "amplify:CreateApp",
        "amplify:CreateBranch",
        "amplify:StartJob",
        # method_76: ModifyInstanceAttribute + StopInstances + StartInstances
        "ec2:ModifyInstanceAttribute",
        "ec2:StopInstances",
        "ec2:StartInstances",
        # method_77: glue:CreateJob + CreateTrigger
        "glue:CreateJob",
        "glue:CreateTrigger",
        # method_79: lambda:CreateFunction + AddPermission (via iam:PassRole already granted)
        "lambda:CreateFunction",
      ]
      Resource = "*"
    }]
  })
}

# =============================================================================
# Service resources — deployed so the recon module creates permission edges
# for the new privesc methods. Resources are minimal (no active compute).
# =============================================================================

# -----------------------------------------------------------------------------
# ECS cluster + task definition + service (0 desired tasks, free)
# Enables: ecs:CreateService (method_54), ecs:RunTask (method_32)
# -----------------------------------------------------------------------------
resource "aws_ecs_cluster" "privesc" {
  name = "${local.prefix}-cluster"
  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_ecs_task_definition" "privesc" {
  family                   = "${local.prefix}-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.passable.arn

  container_definitions = jsonencode([{
    name      = "placeholder"
    image     = "public.ecr.aws/amazonlinux/amazonlinux:2"
    essential = true
    command   = ["sleep", "infinity"]
  }])

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_ecs_service" "privesc" {
  name            = "${local.prefix}-service"
  cluster         = aws_ecs_cluster.privesc.id
  task_definition = aws_ecs_task_definition.privesc.arn
  desired_count   = 0
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.privesc.id]
    security_groups  = [aws_security_group.privesc.id]
    assign_public_ip = false
  }

  tags = { Purpose = "aurelian-privesc-integration-test" }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

resource "aws_vpc" "privesc" {
  cidr_block = "10.99.0.0/16"
  tags       = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_subnet" "privesc" {
  vpc_id            = aws_vpc.privesc.id
  cidr_block        = "10.99.0.0/24"
  availability_zone = "${var.region}a"
  tags              = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_security_group" "privesc" {
  name   = "${local.prefix}-sg"
  vpc_id = aws_vpc.privesc.id
  tags   = { Purpose = "aurelian-privesc-integration-test" }
}

# -----------------------------------------------------------------------------
# Step Functions state machine (express, nearly free when idle)
# Enables: states:CreateStateMachine (method_70), states:UpdateStateMachine (method_71)
# -----------------------------------------------------------------------------
resource "aws_sfn_state_machine" "privesc" {
  name     = "${local.prefix}-statemachine"
  role_arn = aws_iam_role.passable.arn
  type     = "EXPRESS"

  definition = jsonencode({
    Comment = "Aurelian privesc integration test placeholder"
    StartAt = "Pass"
    States = {
      Pass = {
        Type = "Pass"
        End  = true
      }
    }
  })

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

# -----------------------------------------------------------------------------
# EventBridge Scheduler schedule (once-a-year, essentially free)
# Enables: scheduler:CreateSchedule (method_68)
# -----------------------------------------------------------------------------
resource "aws_scheduler_schedule_group" "privesc" {
  name = "${local.prefix}-schedgrp"
  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_scheduler_schedule" "privesc" {
  name       = "privesc-placeholder"
  group_name = aws_scheduler_schedule_group.privesc.name

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "rate(365 days)"

  target {
    arn      = aws_sqs_queue.scheduler_target.arn
    role_arn = aws_iam_role.scheduler.arn

    input = jsonencode({ source = "aurelian-privesc-test" })
  }
}

data "aws_caller_identity" "current" {}

# ECS task execution role (trusts ecs-tasks.amazonaws.com)
resource "aws_iam_role" "ecs_execution" {
  name = "${local.prefix}-ecs-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# EventBridge Scheduler execution role (trusts scheduler.amazonaws.com)
resource "aws_iam_role" "scheduler" {
  name = "${local.prefix}-scheduler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "scheduler.amazonaws.com" }
    }]
  })

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_iam_role_policy" "scheduler" {
  name = "${local.prefix}-scheduler-policy"
  role = aws_iam_role.scheduler.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = aws_sqs_queue.scheduler_target.arn
    }]
  })
}

resource "aws_sqs_queue" "scheduler_target" {
  name = "${local.prefix}-sched-target"
  tags = { Purpose = "aurelian-privesc-integration-test" }
}

# -----------------------------------------------------------------------------
# Glue job (no compute unless triggered)
# Enables: glue:CreateJob (method_60), glue:UpdateJob (method_61)
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "glue_scripts" {
  bucket = "${local.prefix}-glue-scripts"
  tags   = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_s3_object" "glue_script" {
  bucket  = aws_s3_bucket.glue_scripts.id
  key     = "placeholder.py"
  content = "# aurelian privesc integration test placeholder"
}

resource "aws_glue_job" "privesc" {
  name         = "${local.prefix}-glue-job"
  role_arn     = aws_iam_role.passable.arn
  glue_version = "4.0"

  command {
    script_location = "s3://${aws_s3_bucket.glue_scripts.bucket}/${aws_s3_object.glue_script.key}"
    python_version  = "3"
  }

  default_arguments = {
    "--job-language" = "python"
  }

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

# -----------------------------------------------------------------------------
# AWS Batch: compute environment + job queue + job definition (FARGATE_SPOT, free idle)
# Enables: batch:RegisterJobDefinition (method_45), batch:SubmitJob (method_46)
# -----------------------------------------------------------------------------
resource "aws_batch_compute_environment" "privesc" {
  compute_environment_name = "${local.prefix}-batch-ce"
  type                     = "MANAGED"
  # Omit service_role to use the AWS-managed service-linked role AWSServiceRoleForBatch,
  # which has all required ECS permissions without custom IAM setup.

  compute_resources {
    type               = "FARGATE_SPOT"
    max_vcpus          = 4
    security_group_ids = [aws_security_group.privesc.id]
    subnets            = [aws_subnet.privesc.id]
  }

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_batch_job_queue" "privesc" {
  name     = "${local.prefix}-batch-jq"
  state    = "ENABLED"
  priority = 1

  compute_environment_order {
    order               = 1
    compute_environment = aws_batch_compute_environment.privesc.arn
  }

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_batch_job_definition" "privesc" {
  name = "${local.prefix}-batch-jd"
  type = "container"
  platform_capabilities = ["FARGATE"]

  container_properties = jsonencode({
    image   = "public.ecr.aws/amazonlinux/amazonlinux:2"
    command = ["echo", "aurelian-privesc-test"]
    fargatePlatformConfiguration = { platformVersion = "LATEST" }
    resourceRequirements = [
      { type = "VCPU",   value = "0.25" },
      { type = "MEMORY", value = "512" }
    ]
    executionRoleArn = aws_iam_role.ecs_execution.arn
    jobRoleArn       = aws_iam_role.passable.arn
    networkConfiguration = { assignPublicIp = "DISABLED" }
  })

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

# -----------------------------------------------------------------------------
# Cognito Identity Pool (free for unused pools)
# Enables: cognito-identity:SetIdentityPoolRoles (method_51)
# -----------------------------------------------------------------------------
resource "aws_cognito_identity_pool" "privesc" {
  identity_pool_name               = "${local.prefix}-idpool"
  allow_unauthenticated_identities = false

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

# -----------------------------------------------------------------------------
# SageMaker notebook lifecycle configuration (free — just a config object)
# Enables: sagemaker:UpdateNotebookInstanceLifecycleConfig (method_67)
# -----------------------------------------------------------------------------
resource "aws_sagemaker_notebook_instance_lifecycle_configuration" "privesc" {
  name = "${local.prefix}-nb-lc"
}

# -----------------------------------------------------------------------------
# EC2 Image Builder infrastructure configuration (free — just a config object)
# Enables: imagebuilder:CreateInfrastructureConfiguration (method_63)
# -----------------------------------------------------------------------------
resource "aws_imagebuilder_infrastructure_configuration" "privesc" {
  name                  = "${local.prefix}-infra-config"
  instance_profile_name = aws_iam_instance_profile.privesc.name

  tags = { Purpose = "aurelian-privesc-integration-test" }
}

resource "aws_iam_instance_profile" "privesc" {
  name = "${local.prefix}-instance-profile"
  role = aws_iam_role.passable.name
}
