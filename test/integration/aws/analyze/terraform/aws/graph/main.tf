# IAM Privilege Escalation Testing Infrastructure for Graph Integration Tests
#
# Provisions IAM users, roles, groups, and policies to test privilege escalation
# detection in the graph analysis pipeline. Each module creates a specific
# privilege escalation scenario that the graph module should detect.
#
# Adapted from Nebula-Cloud-Infrastructures/Testing Infrastructure/AWS

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-2"
}

# Unique prefix for resource isolation across parallel test runs
resource "random_id" "run" {
  byte_length = 4
}

locals {
  suffix = random_id.run.hex
}

# ==================== IAM PRIVILEGE ESCALATION METHODS ====================

module "iam-createpolicyversion" {
  source        = "./iam-createpolicyversion"
  random_suffix = local.suffix
}

module "iam-setdefaultpolicyversion" {
  source        = "./iam-setdefaultpolicyversion"
  random_suffix = local.suffix
}

module "iam-createaccesskey" {
  source        = "./iam-createaccesskey"
  random_suffix = local.suffix
}

module "iam-createloginprofile" {
  source        = "./iam-createloginprofile"
  random_suffix = local.suffix
}

module "iam-updateloginprofile" {
  source        = "./iam-updateloginprofile"
  random_suffix = local.suffix
}

module "iam-attachuserpolicy" {
  source        = "./iam-attachuserpolicy"
  random_suffix = local.suffix
}

module "iam-attachgrouppolicy" {
  source        = "./iam-attachgrouppolicy"
  random_suffix = local.suffix
}

module "iam-attachrolepolicy" {
  source        = "./iam-attachrolepolicy"
  random_suffix = local.suffix
}

module "iam-putuserpolicy" {
  source        = "./iam-putuserpolicy"
  random_suffix = local.suffix
}

module "iam-putgrouppolicy" {
  source        = "./iam-putgrouppolicy"
  random_suffix = local.suffix
}

module "iam-putrolepolicy" {
  source        = "./iam-putrolepolicy"
  random_suffix = local.suffix
}

module "iam-addusertogroup" {
  source        = "./iam-addusertogroup"
  random_suffix = local.suffix
}

module "iam-updateassumerolepolicy" {
  source        = "./iam-updateassumerolepolicy"
  random_suffix = local.suffix
}

# ==================== SERVICE-BASED PRIVILEGE ESCALATION ====================

module "ec2-runinstances" {
  source        = "./ec2-runinstances"
  random_suffix = local.suffix
}

module "lambda-createfunction" {
  source        = "./lambda-createfunction"
  random_suffix = local.suffix
}

module "lambda-updatefunctioncode" {
  source        = "./lambda-updatefunctioncode"
  random_suffix = local.suffix
}

module "lambda-eventsourcemapping" {
  source        = "./lambda-eventsourcemapping"
  random_suffix = local.suffix
}

module "cloudformation-createstack" {
  source        = "./cloudformation-createstack"
  random_suffix = local.suffix
}

module "ecs-registertaskdefinition" {
  source        = "./ecs-registertaskdefinition"
  random_suffix = local.suffix
}
