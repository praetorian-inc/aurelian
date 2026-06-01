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
  prefix = "aurelian-test-${random_id.run.hex}"
}

# EC2 instances
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "test" {
  count         = 2
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"

  tags = {
    Name = "${local.prefix}-instance-${count.index}"
  }
}

# S3 buckets
resource "aws_s3_bucket" "test" {
  count  = 2
  bucket = "${local.prefix}-bucket-${count.index}"
}

# Lambda functions
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

data "archive_file" "dummy" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"

  source {
    content  = "def handler(event, context): return {'statusCode': 200}"
    filename = "index.py"
  }
}

# IAM resources for IAMEnumerator integration tests
resource "aws_iam_role" "test" {
  name = "${local.prefix}-test-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Deny"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "test" {
  name = "${local.prefix}-test-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = "s3:GetObject"
      Effect   = "Deny"
      Resource = "*"
    }]
  })
}

resource "aws_iam_user" "test" {
  name = "${local.prefix}-test-user"
}

resource "aws_lambda_function" "test" {
  count            = 2
  filename         = data.archive_file.dummy.output_path
  function_name    = "${local.prefix}-function-${count.index}"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy.output_base64sha256
}

# Amplify app (enumerated via custom AmplifyAppEnumerator)
resource "aws_amplify_app" "test" {
  name = "${local.prefix}-amplify-app"
}

resource "aws_amplify_branch" "main" {
  app_id      = aws_amplify_app.test.id
  branch_name = "main"
}

# Restricted role for skip-resilience integration tests.
#
# The policy is designed to trigger multiple error classes in a single run:
#   - S3 + IAM: fully allowed → happy path (resources returned)
#   - Amplify: fully denied → AccessDeniedException from native enumerator
#   - SSM: fully denied → AccessDeniedException from native enumerator (different service)
#   - EC2 images: DescribeImages allowed, DescribeImageAttribute denied
#     → partial failure (list succeeds, enrichment fails per-image)
#   - CloudControl: allowed, but Amplify/SSM calls through CC would also be
#     denied by the service-level deny, exercising the CC skip path too
#
# STS is always allowed (needed for assume-role and GetCallerIdentity).
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "restricted" {
  name = "${local.prefix}-restricted-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = data.aws_caller_identity.current.arn
      }
    }]
  })
}

resource "aws_iam_role_policy" "restricted_allow" {
  name = "${local.prefix}-restricted-allow"
  role = aws_iam_role.restricted.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowPlumbing"
        Effect   = "Allow"
        Action   = ["sts:*", "cloudcontrol:*", "cloudformation:*"]
        Resource = "*"
      },
      {
        Sid      = "AllowS3Full"
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      },
      {
        Sid      = "AllowIAMFull"
        Effect   = "Allow"
        Action   = ["iam:*"]
        Resource = "*"
      },
      {
        Sid      = "AllowEC2DescribeImages"
        Effect   = "Allow"
        Action   = ["ec2:DescribeImages"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "restricted_deny" {
  name = "${local.prefix}-restricted-deny"
  role = aws_iam_role.restricted.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAmplify"
        Effect   = "Deny"
        Action   = ["amplify:*"]
        Resource = "*"
      },
      {
        Sid      = "DenySSM"
        Effect   = "Deny"
        Action   = ["ssm:*"]
        Resource = "*"
      },
      {
        Sid      = "DenyEC2ImageAttributes"
        Effect   = "Deny"
        Action   = ["ec2:DescribeImageAttribute", "ec2:DescribeInstances"]
        Resource = "*"
      }
    ]
  })
}
