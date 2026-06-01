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

provider "aws" {
  alias  = "secondary"
  region = var.secondary_region
}

provider "aws" {
  alias  = "tertiary"
  region = var.tertiary_region
}

resource "random_id" "run" {
  byte_length = 4
}

locals {
  prefix = "aurelian-test-${random_id.run.hex}"
}

# EC2 instances — primary region
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "test" {
  count         = 3
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"

  tags = {
    Name = "${local.prefix}-instance-${count.index}"
  }
}

# EC2 instances — secondary region
data "aws_ami" "amazon_linux_secondary" {
  provider    = aws.secondary
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "test_secondary" {
  provider      = aws.secondary
  count         = 2
  ami           = data.aws_ami.amazon_linux_secondary.id
  instance_type = "t3.micro"

  tags = {
    Name = "${local.prefix}-instance-secondary-${count.index}"
  }
}

# EC2 instances — tertiary region
data "aws_ami" "amazon_linux_tertiary" {
  provider    = aws.tertiary
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "test_tertiary" {
  provider      = aws.tertiary
  count         = 2
  ami           = data.aws_ami.amazon_linux_tertiary.id
  instance_type = "t3.micro"

  tags = {
    Name = "${local.prefix}-instance-tertiary-${count.index}"
  }
}

# S3 buckets — split across regions
resource "aws_s3_bucket" "test" {
  count  = 3
  bucket = "${local.prefix}-bucket-${count.index}"
}

resource "aws_s3_bucket_public_access_block" "test" {
  count                   = 3
  bucket                  = aws_s3_bucket.test[count.index].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "test_secondary" {
  provider = aws.secondary
  count    = 2
  bucket   = "${local.prefix}-bucket-secondary-${count.index}"
}

resource "aws_s3_bucket_public_access_block" "test_secondary" {
  provider                = aws.secondary
  count                   = 2
  bucket                  = aws_s3_bucket.test_secondary[count.index].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "test_tertiary" {
  provider = aws.tertiary
  count    = 2
  bucket   = "${local.prefix}-bucket-tertiary-${count.index}"
}

resource "aws_s3_bucket_public_access_block" "test_tertiary" {
  provider                = aws.tertiary
  count                   = 2
  bucket                  = aws_s3_bucket.test_tertiary[count.index].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lambda functions
resource "aws_iam_role" "lambda" {
  name = "${local.prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

data "archive_file" "dummy" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"

  source {
    content  = "def handler(event, context): return {'statusCode': 200}"
    filename = "index.py"
  }
}

# IAM resources for IAMEnumerator integration tests
resource "aws_iam_role" "test" {
  count = 5
  name  = "${local.prefix}-test-role-${count.index}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Deny"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "test" {
  count = 5
  name  = "${local.prefix}-test-policy-${count.index}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = "s3:GetObject"
      Effect   = "Deny"
      Resource = "*"
    }]
  })
}

resource "aws_iam_user" "test" {
  count = 5
  name  = "${local.prefix}-test-user-${count.index}"
}

resource "aws_lambda_function" "test" {
  count            = 3
  filename         = data.archive_file.dummy.output_path
  function_name    = "${local.prefix}-function-${count.index}"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy.output_base64sha256
}

resource "aws_lambda_function" "test_secondary" {
  provider         = aws.secondary
  count            = 2
  filename         = data.archive_file.dummy.output_path
  function_name    = "${local.prefix}-function-secondary-${count.index}"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy.output_base64sha256
}

resource "aws_lambda_function" "test_tertiary" {
  provider         = aws.tertiary
  count            = 2
  filename         = data.archive_file.dummy.output_path
  function_name    = "${local.prefix}-function-tertiary-${count.index}"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy.output_base64sha256
}

# Amplify app (enumerated via custom AmplifyAppEnumerator)
resource "aws_amplify_app" "test" {
  name = "${local.prefix}-amplify-app"
}

resource "aws_amplify_branch" "main" {
  app_id      = aws_amplify_app.test.id
  branch_name = "main"
}

# Restricted role for skip-resilience integration tests.
#
# The policy is designed to trigger multiple error classes in a single run:
#   - S3 + IAM: fully allowed → happy path (resources returned)
#   - Amplify: fully denied → AccessDeniedException from native enumerator
#   - SSM: fully denied → AccessDeniedException from native enumerator (different service)
#   - EC2 images: DescribeImages allowed, DescribeImageAttribute denied
#     → partial failure (list succeeds, enrichment fails per-image)
#   - CloudControl: allowed, but Amplify/SSM calls through CC would also be
#     denied by the service-level deny, exercising the CC skip path too
#
# STS is always allowed (needed for assume-role and GetCallerIdentity).
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "restricted" {
  name = "${local.prefix}-restricted-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = data.aws_caller_identity.current.arn
      }
    }]
  })
}

resource "aws_iam_role_policy" "restricted_allow" {
  name = "${local.prefix}-restricted-allow"
  role = aws_iam_role.restricted.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowPlumbing"
        Effect   = "Allow"
        Action   = ["sts:*", "cloudcontrol:*", "cloudformation:*"]
        Resource = "*"
      },
      {
        Sid      = "AllowS3"
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      },
      {
        Sid      = "AllowIAM"
        Effect   = "Allow"
        Action   = ["iam:*"]
        Resource = "*"
      },
      {
        Sid      = "AllowEC2"
        Effect   = "Allow"
        Action   = ["ec2:*"]
        Resource = "*"
      },
      {
        Sid      = "AllowLambda"
        Effect   = "Allow"
        Action   = ["lambda:*"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "restricted_deny" {
  name = "${local.prefix}-restricted-deny"
  role = aws_iam_role.restricted.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAmplify"
        Effect   = "Deny"
        Action   = ["amplify:*"]
        Resource = "*"
      },
      {
        Sid      = "DenySSM"
        Effect   = "Deny"
        Action   = ["ssm:*"]
        Resource = "*"
      }
    ]
  })
}

# Partial-access role for EC2 image enrichment tests.
#
# Allows ec2:DescribeImages (list succeeds) but denies
# ec2:DescribeImageAttribute (enrichment fails per-image). This tests
# that the enumerator gracefully degrades — images are found but
# enrichment fails, and the pipeline does not abort.
#
# Also tests ec2:DescribeInstances denied — findInstancesUsingImage
# should return nil gracefully.
resource "aws_iam_role" "partial_ec2" {
  name = "${local.prefix}-partial-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = data.aws_caller_identity.current.arn
      }
    }]
  })
}

resource "aws_iam_role_policy" "partial_ec2_allow" {
  name = "${local.prefix}-partial-ec2-allow"
  role = aws_iam_role.partial_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowPlumbing"
        Effect   = "Allow"
        Action   = ["sts:*", "cloudcontrol:*", "cloudformation:*"]
        Resource = "*"
      },
      {
        Sid      = "AllowEC2List"
        Effect   = "Allow"
        Action   = ["ec2:DescribeImages"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "partial_ec2_deny" {
  name = "${local.prefix}-partial-ec2-deny"
  role = aws_iam_role.partial_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyEC2Enrichment"
        Effect   = "Deny"
        Action   = ["ec2:DescribeImageAttribute", "ec2:DescribeInstances"]
        Resource = "*"
      }
    ]
  })
}

# Per-region mosaic role: different services denied in different regions.
#
# Mosaic pattern across 3 regions:
#   us-east-1: Amplify DENIED, Lambda allowed, S3 allowed
#   us-east-2: Amplify allowed, Lambda DENIED, S3 allowed
#   us-west-2: Amplify allowed, Lambda allowed, S3 allowed (all allowed)
#
# This tests that the enumerator collects resources from each
# (service, region) combination that works, while skipping the
# specific (service, region) pairs that are denied. A bug that aborts
# all regions for a type when one region fails would lose resources.
resource "aws_iam_role" "region_restricted" {
  name = "${local.prefix}-region-restricted-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = data.aws_caller_identity.current.arn
      }
    }]
  })
}

resource "aws_iam_role_policy" "region_restricted_allow" {
  name = "${local.prefix}-region-restricted-allow"
  role = aws_iam_role.region_restricted.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowAll"
        Effect   = "Allow"
        Action   = ["s3:*", "sts:*", "amplify:*", "lambda:*", "ec2:*", "cloudcontrol:*", "cloudformation:*", "iam:*"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "region_restricted_deny" {
  name = "${local.prefix}-region-restricted-deny"
  role = aws_iam_role.region_restricted.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAmplifyInSecondaryRegion"
        Effect   = "Deny"
        Action   = ["amplify:*"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.secondary_region
          }
        }
      },
      {
        Sid      = "DenyLambdaInPrimaryRegion"
        Effect   = "Deny"
        Action   = ["lambda:*"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.region
          }
        }
      }
    ]
  })
}
