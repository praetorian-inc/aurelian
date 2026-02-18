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
  prefix = "aurelian-graph-${random_id.run.hex}"
}

# -----------------------------------------------------------------------------
# IAM Users
# -----------------------------------------------------------------------------
resource "aws_iam_user" "test" {
  count = 2
  name  = "${local.prefix}-user-${count.index}"

  tags = {
    Purpose = "aurelian-integration-test"
  }
}

# Inline policy on user 0 — privesc-relevant actions so the IAM analyzer
# produces FullResult relationships for this user.
resource "aws_iam_user_policy" "inline" {
  name = "${local.prefix}-inline-policy"
  user = aws_iam_user.test[0].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.test.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:CreateLoginProfile",
          "iam:AttachUserPolicy",
          "iam:PutUserPolicy",
          "sts:AssumeRole",
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach managed policy to user 1 — also give privesc-relevant permissions
resource "aws_iam_user_policy" "user1_privesc" {
  name = "${local.prefix}-user1-privesc"
  user = aws_iam_user.test[1].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
      ]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# IAM Group with user membership
# -----------------------------------------------------------------------------
resource "aws_iam_group" "test" {
  name = "${local.prefix}-group"
}

resource "aws_iam_group_membership" "test" {
  name  = "${local.prefix}-group-membership"
  group = aws_iam_group.test.name
  users = [aws_iam_user.test[0].name]
}

resource "aws_iam_group_policy" "test" {
  name  = "${local.prefix}-group-policy"
  group = aws_iam_group.test.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:Describe*"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# IAM Roles
# -----------------------------------------------------------------------------

# Role assumable by Lambda
resource "aws_iam_role" "lambda" {
  name = "${local.prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = {
    Purpose = "aurelian-integration-test"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Role assumable by user 0 (cross-principal trust)
resource "aws_iam_role" "assumable" {
  name = "${local.prefix}-assumable-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.test[0].arn }
    }]
  })

  tags = {
    Purpose = "aurelian-integration-test"
  }
}

resource "aws_iam_role_policy" "assumable_inline" {
  name = "${local.prefix}-assumable-inline"
  role = aws_iam_role.assumable.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:ListUsers"]
      Resource = "*"
    }]
  })
}

# -----------------------------------------------------------------------------
# Customer-managed IAM Policy
# -----------------------------------------------------------------------------
resource "aws_iam_policy" "custom" {
  name        = "${local.prefix}-custom-policy"
  description = "Custom policy for graph integration test"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeInstances"]
      Resource = "*"
    }]
  })

  tags = {
    Purpose = "aurelian-integration-test"
  }
}

resource "aws_iam_role_policy_attachment" "custom_to_assumable" {
  role       = aws_iam_role.assumable.name
  policy_arn = aws_iam_policy.custom.arn
}

# -----------------------------------------------------------------------------
# S3 Bucket with resource policy
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "test" {
  bucket = "${local.prefix}-bucket"
}

resource "aws_s3_bucket_policy" "test" {
  bucket = aws_s3_bucket.test.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowUserRead"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.test[0].arn }
      Action    = ["s3:GetObject"]
      Resource  = "${aws_s3_bucket.test.arn}/*"
    }]
  })
}

# -----------------------------------------------------------------------------
# SQS Queue with resource policy
# -----------------------------------------------------------------------------
resource "aws_sqs_queue" "test" {
  name = "${local.prefix}-queue"

  tags = {
    Purpose = "aurelian-integration-test"
  }
}

resource "aws_sqs_queue_policy" "test" {
  queue_url = aws_sqs_queue.test.url

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowRoleSend"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.lambda.arn }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.test.arn
    }]
  })
}

# -----------------------------------------------------------------------------
# SNS Topic with resource policy
# -----------------------------------------------------------------------------
resource "aws_sns_topic" "test" {
  name = "${local.prefix}-topic"

  tags = {
    Purpose = "aurelian-integration-test"
  }
}

resource "aws_sns_topic_policy" "test" {
  arn = aws_sns_topic.test.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowPublish"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.lambda.arn }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.test.arn
    }]
  })
}

# -----------------------------------------------------------------------------
# Lambda function (resource with policy + uses the lambda role)
# -----------------------------------------------------------------------------
data "archive_file" "dummy" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"

  source {
    content  = "def handler(event, context): return {'statusCode': 200}"
    filename = "index.py"
  }
}

resource "aws_lambda_function" "test" {
  filename         = data.archive_file.dummy.output_path
  function_name    = "${local.prefix}-function"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy.output_base64sha256

  tags = {
    Purpose = "aurelian-integration-test"
  }
}

# Lambda resource policy allowing SNS to invoke it
resource "aws_lambda_permission" "sns" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.test.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.test.arn
}
