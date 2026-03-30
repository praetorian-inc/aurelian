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
  prefix = "aurelian-list-admin-${random_id.run.hex}"
}

resource "aws_iam_user" "admin" {
  name = "${local.prefix}-admin-user"
}

resource "aws_iam_user_policy_attachment" "admin_user" {
  user       = aws_iam_user.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "non_admin" {
  name = "${local.prefix}-non-admin-user"
}

resource "aws_iam_user_policy" "non_admin_user" {
  name = "${local.prefix}-non-admin-user-inline"
  user = aws_iam_user.non_admin.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:ListAllMyBuckets"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "admin" {
  name = "${local.prefix}-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin_role" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role" "non_admin" {
  name = "${local.prefix}-non-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "non_admin_role" {
  name = "${local.prefix}-non-admin-role-inline"
  role = aws_iam_role.non_admin.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "admin" {
  name = "${local.prefix}-admin-group"
}

resource "aws_iam_group_policy_attachment" "admin_group" {
  group      = aws_iam_group.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "admin_group_member" {
  name = "${local.prefix}-admin-group-member"
}

resource "aws_iam_group_membership" "admin_group" {
  name  = "${local.prefix}-admin-group-membership"
  group = aws_iam_group.admin.name
  users = [aws_iam_user.admin_group_member.name]
}

resource "aws_iam_group" "non_admin" {
  name = "${local.prefix}-non-admin-group"
}

resource "aws_iam_group_policy" "non_admin_group" {
  name  = "${local.prefix}-non-admin-group-inline"
  group = aws_iam_group.non_admin.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:DescribeLogGroups"]
      Resource = "*"
    }]
  })
}
