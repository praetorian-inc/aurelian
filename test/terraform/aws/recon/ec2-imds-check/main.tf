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
  prefix = "aurelian-imds-${random_id.run.hex}"
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# TC1: IMDSv1 allowed (should be flagged)
resource "aws_instance" "imdsv1_allowed" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"

  metadata_options {
    http_tokens   = "optional"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "${local.prefix}-imdsv1-allowed"
  }
}

# TC2: IMDSv2 enforced (should NOT be flagged)
resource "aws_instance" "imdsv2_enforced" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "${local.prefix}-imdsv2-enforced"
  }
}

# TC3: IMDS disabled (should NOT be flagged)
resource "aws_instance" "imds_disabled" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "disabled"
  }

  tags = {
    Name = "${local.prefix}-imds-disabled"
  }
}
