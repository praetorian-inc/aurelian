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

  backend "s3" {}
}

provider "aws" {
  region = var.region
}

resource "random_id" "run" {
  byte_length = 4
}

locals {
  prefix = "aurelian-sec-${random_id.run.hex}"
  # Intentionally fake credentials used only for secret-detection testing.
  fake_aws_key    = "AKIAIOSFODNN7EXAMPLE"
  fake_aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ============================================================
# Shared IAM roles
# ============================================================
resource "aws_iam_role" "lambda" {
  name = "${local.prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role" "ecs_task_execution" {
  name = "${local.prefix}-ecs-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role" "sfn" {
  name = "${local.prefix}-sfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
    }]
  })
}

# ============================================================
# 1. EC2 Instance — secret in user data
# ============================================================
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "with_secret" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"

  user_data = <<-EOF
    #!/bin/bash
    export AWS_ACCESS_KEY_ID="${local.fake_aws_key}"
    export AWS_SECRET_ACCESS_KEY="${local.fake_aws_secret}"
    echo "configured"
  EOF

  tags = {
    Name = "${local.prefix}-secret-ec2"
  }
}

# ============================================================
# 2. Lambda Function — secret in source code
# ============================================================
data "archive_file" "lambda_with_secret" {
  type        = "zip"
  output_path = "${path.module}/lambda_secret.zip"

  source {
    content  = <<-PYEOF
      import os
      def handler(event, context):
          api_key = "AKIAIOSFODNN7EXAMPLE"
          secret  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
          return {"statusCode": 200}
    PYEOF
    filename = "index.py"
  }
}

resource "aws_lambda_function" "with_secret" {
  filename         = data.archive_file.lambda_with_secret.output_path
  function_name    = "${local.prefix}-secret-lambda"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_with_secret.output_base64sha256
}

# ============================================================
# 3. CloudFormation Stack — secret in template parameter default
# ============================================================
resource "aws_cloudformation_stack" "with_secret" {
  name = "${local.prefix}-secret-cfn"

  template_body = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Description              = "Test stack with hardcoded secret"
    Resources = {
      NullResource = {
        Type = "AWS::CloudFormation::WaitConditionHandle"
      }
    }
    Outputs = {
      AccessKeyId = {
        Value = local.fake_aws_key
      }
      SecretAccessKey = {
        Value = local.fake_aws_secret
      }
    }
  })

  tags = {
    Name = "${local.prefix}-secret-cfn"
  }
}

# ============================================================
# 4. CloudWatch Log Group — secret written to log stream
# ============================================================
resource "aws_cloudwatch_log_group" "with_secret" {
  name              = "/${local.prefix}/secret-logs"
  retention_in_days = 1
}

resource "aws_cloudwatch_log_stream" "with_secret" {
  name           = "secret-stream"
  log_group_name = aws_cloudwatch_log_group.with_secret.name
}

# Write a log event containing a fake secret via local-exec.
resource "null_resource" "write_log_event" {
  depends_on = [aws_cloudwatch_log_stream.with_secret]

  provisioner "local-exec" {
    command = <<-CMD
      aws logs put-log-events \
        --region ${var.region} \
        --log-group-name "${aws_cloudwatch_log_group.with_secret.name}" \
        --log-stream-name "${aws_cloudwatch_log_stream.with_secret.name}" \
        --log-events '[{"timestamp":'$(date +%s000)',"message":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}]'
    CMD
  }
}

# ============================================================
# 5. ECS Task Definition — secret in container environment
# ============================================================
resource "aws_ecs_task_definition" "with_secret" {
  family                   = "${local.prefix}-secret-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([{
    name      = "secret-container"
    image     = "alpine:latest"
    essential = true
    environment = [
      { name = "AWS_ACCESS_KEY_ID", value = local.fake_aws_key },
      { name = "AWS_SECRET_ACCESS_KEY", value = local.fake_aws_secret },
    ]
  }])
}

# ============================================================
# 6. SSM Document — secret in document content
# ============================================================
resource "aws_ssm_document" "with_secret" {
  name            = "${local.prefix}-secret-doc"
  document_type   = "Command"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Test document with hardcoded secret"
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "runWithSecret"
      inputs = {
        runCommand = [
          "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
          "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ]
      }
    }]
  })
}

# ============================================================
# 7. Step Functions State Machine — secret in execution input
# ============================================================
resource "aws_sfn_state_machine" "with_secret" {
  name     = "${local.prefix}-secret-sfn"
  role_arn = aws_iam_role.sfn.arn

  definition = jsonencode({
    Comment = "Test state machine"
    StartAt = "Pass"
    States = {
      Pass = {
        Type = "Pass"
        Result = {
          aws_key    = "AKIAIOSFODNN7EXAMPLE"
          aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        }
        End = true
      }
    }
  })
}

# Start an execution so the extractor has something to scan.
resource "null_resource" "start_sfn_execution" {
  depends_on = [aws_sfn_state_machine.with_secret]

  provisioner "local-exec" {
    command = <<-CMD
      aws stepfunctions start-execution \
        --region ${var.region} \
        --state-machine-arn "${aws_sfn_state_machine.with_secret.arn}" \
        --input '{"aws_key":"AKIAIOSFODNN7EXAMPLE","aws_secret":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}'
    CMD
  }
}
