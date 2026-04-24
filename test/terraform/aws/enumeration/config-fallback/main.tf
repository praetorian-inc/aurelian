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

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  tags = {
    aurelian-fixture = "config-fallback"
    aurelian-issue   = "LAB-2525"
  }
}

# --- Target resource we want to discover via Config fallback ---

resource "aws_s3_bucket" "target" {
  bucket        = "${var.name_prefix}-${random_id.suffix.hex}"
  force_destroy = true
  tags          = local.tags
}

# --- Config recorder wiring ---
# Minimal viable config: delivery channel to an S3 bucket + recorder + recording group.

# The delivery bucket name MUST start with "aws-config-" or "config-bucket-"
# for the AWS-managed AWS_ConfigRole policy to grant s3:PutObject. Renaming this
# bucket without also broadening the role's permissions will cause the recorder
# to silently fail to deliver configuration snapshots.
resource "aws_s3_bucket" "config_delivery" {
  bucket        = "aws-config-${var.name_prefix}-${random_id.suffix.hex}"
  force_destroy = true
  tags          = local.tags
}

resource "aws_s3_bucket_policy" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id
  policy = data.aws_iam_policy_document.config_delivery.json
}

data "aws_iam_policy_document" "config_delivery" {
  statement {
    sid    = "AllowConfigWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config_delivery.arn}/AWSLogs/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  statement {
    sid    = "AllowConfigRead"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config_delivery.arn]
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.name_prefix}-${random_id.suffix.hex}-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "config_assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.name_prefix}-${random_id.suffix.hex}"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.name_prefix}-${random_id.suffix.hex}"
  s3_bucket_name = aws_s3_bucket.config_delivery.bucket
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}
