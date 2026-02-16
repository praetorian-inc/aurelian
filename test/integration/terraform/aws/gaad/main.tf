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
  prefix = "aurelian-gaad-${random_id.run.hex}"
}

# --- IAM Managed Policy ---
resource "aws_iam_policy" "test" {
  name        = "${local.prefix}-policy"
  description = "Aurelian GAAD integration test policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "arn:aws:s3:::${local.prefix}-fake-bucket/*"
    }]
  })
}

# --- IAM Group ---
resource "aws_iam_group" "test" {
  name = "${local.prefix}-group"
  path = "/aurelian-test/"
}

resource "aws_iam_group_policy_attachment" "test" {
  group      = aws_iam_group.test.name
  policy_arn = aws_iam_policy.test.arn
}

# --- IAM User ---
resource "aws_iam_user" "test" {
  name = "${local.prefix}-user"
  path = "/aurelian-test/"
}

resource "aws_iam_user_group_membership" "test" {
  user   = aws_iam_user.test.name
  groups = [aws_iam_group.test.name]
}

resource "aws_iam_user_policy_attachment" "test" {
  user       = aws_iam_user.test.name
  policy_arn = aws_iam_policy.test.arn
}

# --- IAM Role ---
resource "aws_iam_role" "test" {
  name = "${local.prefix}-role"
  path = "/aurelian-test/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "test" {
  role       = aws_iam_role.test.name
  policy_arn = aws_iam_policy.test.arn
}
