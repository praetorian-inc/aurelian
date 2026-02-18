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
  prefix = "aurelian-fs-${random_id.run.hex}"
  # A fake AWS access key for testing (NOT real credentials)
  test_secret = "AKIAIOSFODNN7EXAMPLE"
}

# EC2 Instance with UserData containing a fake secret
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "test" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"

  user_data = base64encode(<<-EOF
    #!/bin/bash
    # Test script with embedded fake credentials
    export AWS_ACCESS_KEY_ID="${local.test_secret}"
    export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    echo "Setup complete"
  EOF
  )

  tags = {
    Name = "${local.prefix}-ec2"
  }
}

# Lambda function with code containing a fake secret
data "archive_file" "lambda_code" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"

  source {
    content  = <<-EOF
      import os

      def handler(event, context):
          # Fake credentials for testing
          api_key = "AKIAIOSFODNN7EXAMPLE"
          secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
          return {"statusCode": 200, "body": "ok"}
    EOF
    filename = "handler.py"
  }
}

resource "aws_iam_role" "lambda" {
  name = "${local.prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_lambda_function" "test" {
  function_name    = "${local.prefix}-lambda"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_code.output_path
  source_code_hash = data.archive_file.lambda_code.output_base64sha256

  tags = {
    Name = "${local.prefix}-lambda"
  }
}

# CloudFormation stack with a template containing a fake secret
resource "aws_cloudformation_stack" "test" {
  name = "${local.prefix}-stack"

  template_body = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Description              = "Test stack with embedded fake credentials"
    Parameters = {
      ApiKey = {
        Type    = "String"
        Default = "AKIAIOSFODNN7EXAMPLE"
      }
    }
    Resources = {
      NullResource = {
        Type = "AWS::CloudFormation::WaitConditionHandle"
      }
    }
    Outputs = {
      TestKey = {
        Value = { Ref = "ApiKey" }
      }
    }
  })

  tags = {
    Name = "${local.prefix}-stack"
  }
}

# CloudWatch Log Group with events containing fake secrets
resource "aws_cloudwatch_log_group" "test" {
  name              = "/aurelian/${local.prefix}/test"
  retention_in_days = 1

  tags = {
    Name = "${local.prefix}-logs"
  }
}

resource "aws_cloudwatch_log_stream" "test" {
  name           = "test-stream"
  log_group_name = aws_cloudwatch_log_group.test.name
}

# Put log events with fake secrets using a local-exec provisioner
resource "null_resource" "log_events" {
  depends_on = [aws_cloudwatch_log_stream.test]

  provisioner "local-exec" {
    command = <<-CMD
      TIMESTAMP=$(date +%s)000
      aws logs put-log-events \
        --log-group-name "${aws_cloudwatch_log_group.test.name}" \
        --log-stream-name "${aws_cloudwatch_log_stream.test.name}" \
        --log-events "[{\"timestamp\":$TIMESTAMP,\"message\":\"Starting application with api_key=AKIAIOSFODNN7EXAMPLE\"},{\"timestamp\":$((TIMESTAMP+1)),\"message\":\"Using secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"},{\"timestamp\":$((TIMESTAMP+2)),\"message\":\"Application started successfully\"}]" \
        --region ${var.region}
    CMD
  }
}
