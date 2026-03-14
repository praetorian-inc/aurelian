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

  backend "s3" {}
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
  prefix = "aurelian-ami-test-${random_id.run.hex}"
}

resource "aws_ec2_image_block_public_access" "unblock" {
  state = "unblocked"
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-minimal-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_ami_copy" "public_in_use" {
  name              = "${local.prefix}-public-in-use"
  description       = "Public AMI for integration testing (in-use)"
  source_ami_id     = data.aws_ami.amazon_linux.id
  source_ami_region = var.region

  tags = { Name = "${local.prefix}-public-in-use" }

  lifecycle { ignore_changes = [deprecation_time] }
}

resource "aws_ami_launch_permission" "public_in_use" {
  image_id   = aws_ami_copy.public_in_use.id
  group      = "all"
  depends_on = [aws_ec2_image_block_public_access.unblock]
}

resource "aws_ami_copy" "public_stale" {
  name              = "${local.prefix}-public-stale"
  description       = "Public AMI for integration testing (stale, no instances)"
  source_ami_id     = data.aws_ami.amazon_linux.id
  source_ami_region = var.region

  tags = { Name = "${local.prefix}-public-stale" }

  lifecycle { ignore_changes = [deprecation_time] }
}

resource "aws_ami_launch_permission" "public_stale" {
  image_id   = aws_ami_copy.public_stale.id
  group      = "all"
  depends_on = [aws_ec2_image_block_public_access.unblock]
}

resource "aws_ami_copy" "private" {
  name              = "${local.prefix}-private"
  description       = "Private AMI for integration testing"
  source_ami_id     = data.aws_ami.amazon_linux.id
  source_ami_region = var.region

  tags = { Name = "${local.prefix}-private" }

  lifecycle { ignore_changes = [deprecation_time] }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "availability-zone"
    values = ["${var.region}a"]
  }
}

resource "aws_instance" "using_public_ami" {
  ami           = aws_ami_copy.public_in_use.id
  instance_type = "t3.micro"
  subnet_id     = data.aws_subnets.default.ids[0]

  tags = { Name = "${local.prefix}-using-public-ami" }

  depends_on = [aws_ami_launch_permission.public_in_use]
}
