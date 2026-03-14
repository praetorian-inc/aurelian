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
    # Configured via -backend-config at init time
  }
}

provider "aws" {
  region = var.region
}

resource "random_id" "run" {
  byte_length = 4
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  prefix    = "aurelian-cdk-${random_id.run.hex}"
  qualifier = "at${random_id.run.hex}"
  account   = data.aws_caller_identity.current.account_id
  region    = data.aws_region.current.name

  # Second qualifier: roles exist but NO S3 bucket → triggers cdk-bucket-takeover
  qualifier_no_bucket = "bt${random_id.run.hex}"

  # Third qualifier: roles exist but NO SSM param → triggers cdk-bootstrap-missing + cdk-bucket-takeover
  qualifier_no_ssm = "ct${random_id.run.hex}"
}

# SSM Parameter simulating CDK bootstrap version (outdated: 20 < 21)
resource "aws_ssm_parameter" "cdk_version" {
  name  = "/cdk-bootstrap/${local.qualifier}/version"
  type  = "String"
  value = "20"
}

# S3 bucket matching CDK staging bucket naming convention
resource "aws_s3_bucket" "cdk_staging" {
  bucket        = "cdk-${local.qualifier}-assets-${local.account}-${local.region}"
  force_destroy = true
}

# IAM role matching CDK file-publishing-role naming pattern
resource "aws_iam_role" "file_publishing" {
  name = "cdk-${local.qualifier}-file-publishing-role-${local.account}-${local.region}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "cloudformation.amazonaws.com" }
    }]
  })
}

# Inline policy with S3 actions but WITHOUT aws:ResourceAccount condition
# This should trigger a policy risk detection (TM severity)
resource "aws_iam_role_policy" "file_publishing_s3" {
  name = "cdk-${local.qualifier}-file-publishing-s3"
  role = aws_iam_role.file_publishing.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject*",
        "s3:PutObject*",
        "s3:GetBucket*"
      ]
      Resource = [
        aws_s3_bucket.cdk_staging.arn,
        "${aws_s3_bucket.cdk_staging.arn}/*"
      ]
    }]
  })
}

# IAM role matching CDK deploy-role naming pattern
resource "aws_iam_role" "deploy" {
  name = "cdk-${local.qualifier}-deploy-role-${local.account}-${local.region}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "cloudformation.amazonaws.com" }
    }]
  })
}

# --- Qualifier 2: roles + SSM but NO bucket (triggers cdk-bucket-takeover) ---

resource "aws_ssm_parameter" "cdk_version_no_bucket" {
  name  = "/cdk-bootstrap/${local.qualifier_no_bucket}/version"
  type  = "String"
  value = "20"
}

resource "aws_iam_role" "file_publishing_no_bucket" {
  name = "cdk-${local.qualifier_no_bucket}-file-publishing-role-${local.account}-${local.region}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "cloudformation.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "file_publishing_s3_no_bucket" {
  name = "cdk-${local.qualifier_no_bucket}-file-publishing-s3"
  role = aws_iam_role.file_publishing_no_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject*", "s3:PutObject*"]
      Resource = "arn:aws:s3:::cdk-${local.qualifier_no_bucket}-assets-${local.account}-${local.region}/*"
    }]
  })
}

# --- Qualifier 3: roles but NO SSM param and NO bucket (triggers cdk-bootstrap-missing + cdk-bucket-takeover) ---

resource "aws_iam_role" "file_publishing_no_ssm" {
  name = "cdk-${local.qualifier_no_ssm}-file-publishing-role-${local.account}-${local.region}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "cloudformation.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "file_publishing_s3_no_ssm" {
  name = "cdk-${local.qualifier_no_ssm}-file-publishing-s3"
  role = aws_iam_role.file_publishing_no_ssm.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject*", "s3:PutObject*"]
      Resource = "arn:aws:s3:::cdk-${local.qualifier_no_ssm}-assets-${local.account}-${local.region}/*"
    }]
  })
}
