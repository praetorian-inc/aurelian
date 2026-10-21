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

  backend "s3" {}
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

resource "random_id" "run" {
  byte_length = 4
}

# Fixture for find-secrets partial-failure behavior (ENG-8768).
#
# Each secret-bearing resource type gets a "readable" and a "locked" twin. The
# scan role is ReadOnlyAccess plus explicit denies that hit the locked twin at
# a specific find-secrets layer:
#
#   - locked Lambda: lambda:GetFunction denied. The ARN lister (EnumerateByARN)
#     and the extractor both call GetFunction, so the lister fails first and
#     records the resource in the skip report.
#   - locked stack: cloudformation:GetTemplate denied. The lister only needs
#     DescribeStacks, so the resource is listed and the extractor fails.
locals {
  prefix = "aurelian-partial-${random_id.run.hex}"
}

# ============================================================
# Lambda functions
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

# Written under .terraform/ so the generated zip is excluded from the fixture hash.
data "archive_file" "lambda" {
  type        = "zip"
  output_path = "${path.module}/.terraform/lambda_partial.zip"

  source {
    content  = <<-PYEOF
      def handler(event, context):
          api_key = "AKIAIOSFODNN7EXAMPLE"
          secret  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
          return {"statusCode": 200}
    PYEOF
    filename = "index.py"
  }
}

resource "aws_lambda_function" "readable" {
  filename         = data.archive_file.lambda.output_path
  function_name    = "${local.prefix}-readable"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda.output_base64sha256
}

resource "aws_lambda_function" "locked" {
  filename         = data.archive_file.lambda.output_path
  function_name    = "${local.prefix}-locked"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda.output_base64sha256
}

# ============================================================
# CloudFormation stacks (secret in template outputs)
# ============================================================
locals {
  stack_template = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Description              = "find-secrets partial-failure fixture"
    Resources = {
      NullResource = { Type = "AWS::CloudFormation::WaitConditionHandle" }
    }
    Outputs = {
      AccessKeyId     = { Value = "AKIAIOSFODNN7EXAMPLE" }
      SecretAccessKey = { Value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }
    }
  })
}

resource "aws_cloudformation_stack" "readable" {
  name          = "${local.prefix}-readable"
  template_body = local.stack_template
}

resource "aws_cloudformation_stack" "locked" {
  name          = "${local.prefix}-locked"
  template_body = local.stack_template
}

# ============================================================
# Scan role: ReadOnlyAccess minus the locked twins
# ============================================================
resource "aws_iam_role" "scan" {
  name = "${local.prefix}-scan"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "scan_readonly" {
  role       = aws_iam_role.scan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy" "scan_deny_locked" {
  name = "${local.prefix}-deny-locked"
  role = aws_iam_role.scan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyLockedLambda"
        Effect   = "Deny"
        Action   = ["lambda:GetFunction"]
        Resource = [aws_lambda_function.locked.arn]
      },
      {
        Sid      = "DenyLockedStackTemplate"
        Effect   = "Deny"
        Action   = ["cloudformation:GetTemplate"]
        Resource = [aws_cloudformation_stack.locked.id]
      },
    ]
  })
}
