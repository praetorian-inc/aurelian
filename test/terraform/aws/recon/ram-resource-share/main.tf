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

resource "random_id" "run" {
  byte_length = 4
}

resource "aws_ram_resource_share" "external" {
  name                      = "aurelian-it-external-share-${random_id.run.hex}"
  allow_external_principals = true
}

resource "aws_ram_principal_association" "external" {
  resource_share_arn = aws_ram_resource_share.external.arn
  principal          = var.external_account_id
}

resource "aws_ram_resource_share" "org_only" {
  name                      = "aurelian-it-org-only-share-${random_id.run.hex}"
  allow_external_principals = false
}
