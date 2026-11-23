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
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
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
  prefix = "aurelian-tech-${random_id.run.hex}"
}

# ---------------------------------------------------------------------------
# Tier 2 — container image references on an ECS task definition.
#
# Registering a task definition is free and instantaneous: nothing is scheduled,
# no cluster exists, no capacity is reserved. ContainerDefinitions[].Image also
# arrives complete and inline from CloudControl ListResources, so this exercises
# the tier-2 path with no hydration.
#
# Two containers, chosen as a positive and a negative control:
#
#   nginx:1.25.3  MUST emit cpe:2.3:a:f5:nginx:1.25.3:*:...
#                 f5, not nginx. NVD deprecated every nginx:nginx record in
#                 favour of f5:nginx, and the deprecation chain spans feed
#                 chunks, so a generator that resolved per chunk published the
#                 dead vendor. This asserts the live one reaches a real scan.
#
#   alpine:3.19   MUST emit nothing.
#                 CPE files operating systems under part "o" and the generator
#                 keeps only part "a", so the only "alpine" product in the
#                 dictionary is alpine_project:alpine — the Pine-successor
#                 EMAIL CLIENT. One vendor, so the sole-vendor rule would fire
#                 for every version and stamp an email client's identity onto
#                 the most common container base image there is.
# ---------------------------------------------------------------------------
resource "aws_ecs_task_definition" "technology" {
  family       = "${local.prefix}-taskdef"
  network_mode = "bridge"

  container_definitions = jsonencode([
    {
      name      = "versioned-server"
      image     = "nginx:1.25.3"
      cpu       = 0
      memory    = 128
      essential = true
    },
    {
      name      = "os-base-image"
      image     = "alpine:3.19"
      cpu       = 0
      memory    = 128
      essential = false
    },
  ])
}

# ---------------------------------------------------------------------------
# Tier 1 — Lambda runtime strings.
#
# Lambda's ListResources payload omits Runtime entirely, so these two functions
# are also the only end-to-end proof that the enricher's hydrateIfMissing call
# fires. Without it both emit nothing and the positive control below fails.
#
#   java21      MUST emit cpe:2.3:a:oracle:openjdk:21:*:...
#   python3.12  MUST emit nothing — "python" carries several live vendors, so a
#               minor-only version is undecidable and rule 3 drops it.
#
# Deliberately a matched pair: a test that only asserted java21 could not tell
# correct resolution apart from a decoder that emits for every runtime it sees.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "lambda" {
  name = "${local.prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# Never invoked — Lambda does not validate archive contents at create time, and
# the test reads the Runtime property rather than running any code.
data "archive_file" "stub" {
  type        = "zip"
  output_path = "${path.module}/stub.zip"

  source {
    content  = "stub"
    filename = "stub.txt"
  }
}

resource "aws_lambda_function" "resolvable_runtime" {
  filename         = data.archive_file.stub.output_path
  function_name    = "${local.prefix}-java"
  role             = aws_iam_role.lambda.arn
  handler          = "example.Handler::handleRequest"
  runtime          = "java21"
  source_code_hash = data.archive_file.stub.output_base64sha256
}

resource "aws_lambda_function" "undecidable_runtime" {
  filename         = data.archive_file.stub.output_path
  function_name    = "${local.prefix}-python"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.stub.output_base64sha256
}
