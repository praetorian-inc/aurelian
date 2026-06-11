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

variable "region" {
  default = "us-east-1"
}

resource "random_id" "run" {
  byte_length = 4
}

locals {
  prefix = "aurelian-cognito-enricher-${random_id.run.hex}"
}

resource "aws_cognito_user_pool" "test" {
  name = "${local.prefix}-pool"

  admin_create_user_config {
    allow_admin_create_user_only = true
  }
}

resource "aws_iam_role" "group" {
  name = "${local.prefix}-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "cognito-idp.amazonaws.com"
      }
    }]
  })
}

resource "aws_cognito_user_group" "admins" {
  name         = "${local.prefix}-admins"
  user_pool_id = aws_cognito_user_pool.test.id
  role_arn     = aws_iam_role.group.arn
  precedence   = 1
}
