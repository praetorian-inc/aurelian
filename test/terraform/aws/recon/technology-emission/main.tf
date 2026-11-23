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

# ===========================================================================
# Tier 2 — container image references on ECS task definitions.
#
# Registering a task definition is free and instantaneous: nothing is
# scheduled, no cluster exists, no capacity is reserved. ContainerDefinitions
# also arrives complete and inline from CloudControl ListResources, so this
# exercises the tier-2 path with no hydration.
#
# Three task definitions rather than one, so every expected CPE set is
# unambiguously attributable to the images in that one resource.
# ===========================================================================

# --- 1. Controls: the vendor-correctness pair --------------------------------
#
#   nginx:1.25.3  MUST emit cpe:2.3:a:f5:nginx:1.25.3:*:...
#                 f5, not nginx. NVD deprecated every nginx:nginx record in
#                 favour of f5:nginx, and the deprecation chain spans feed
#                 chunks, so a generator that resolved per chunk published the
#                 dead vendor.
#
#   alpine:3.19   MUST emit nothing.
#                 CPE files operating systems under part "o" and the generator
#                 keeps only part "a", so the only "alpine" product in the
#                 dictionary is alpine_project:alpine — the Pine-successor
#                 EMAIL CLIENT. One vendor, so the sole-vendor rule would fire
#                 for every version and stamp an email client's identity onto
#                 the most common container base image there is.
resource "aws_ecs_task_definition" "controls" {
  family       = "${local.prefix}-controls"
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

# --- 2. Reference parsing ----------------------------------------------------
#
# Four images, three expected CPEs. Each isolates one parsing rule:
#
#   public.ecr.aws/docker/library/postgres:15.4
#                        registry-qualified name — the registry host and
#                        namespace must be stripped before lookup.
#                        -> postgresql:postgresql:15.4
#
#   httpd:2.4.58         image name != CPE product. "httpd" must map to
#                        apache:http_server, which no naive
#                        image-name-as-product lookup would find.
#                        -> apache:http_server:2.4.58
#
#   nginx:1.25.3-alpine  suffixed tag. The version must survive the "-alpine"
#                        variant suffix, AND the suffix must not drag in the
#                        alpine email client.
#                        -> f5:nginx:1.25.3
#
#   nginx:latest         MUST emit nothing. A tag carrying no parseable
#                        version. This is the realistic case: the only image
#                        reference in the whole harvest account was
#                        "alpine:latest".
resource "aws_ecs_task_definition" "parsing" {
  family       = "${local.prefix}-parsing"
  network_mode = "bridge"

  container_definitions = jsonencode([
    {
      name      = "registry-qualified"
      image     = "public.ecr.aws/docker/library/postgres:15.4"
      cpu       = 0
      memory    = 128
      essential = true
    },
    {
      name      = "product-name-differs"
      image     = "httpd:2.4.58"
      cpu       = 0
      memory    = 128
      essential = false
    },
    {
      name      = "variant-suffixed-tag"
      image     = "nginx:1.25.3-alpine"
      cpu       = 0
      memory    = 128
      essential = false
    },
    {
      name      = "unversioned-tag"
      image     = "nginx:latest"
      cpu       = 0
      memory    = 128
      essential = false
    },
  ])
}

# --- 3. Sibling distributions ------------------------------------------------
#
#   redis:6.2.6  emits TWO CPEs — redis:redis and redislabs:redis.
#
# Both vendors are live in the dictionary for product "redis", so resolution
# cannot choose between them and emits both. The PR lists this under known
# gaps ("rule 1 can emit sibling distributions"). It is pinned here rather than
# left unasserted so that narrowing it later shows up as a test diff instead of
# a silent change in customer inventory.
resource "aws_ecs_task_definition" "siblings" {
  family       = "${local.prefix}-siblings"
  network_mode = "bridge"

  container_definitions = jsonencode([
    {
      name      = "multi-vendor-product"
      image     = "redis:6.2.6"
      cpu       = 0
      memory    = 128
      essential = true
    },
  ])
}

# ===========================================================================
# Tier 1 — Lambda runtime strings.
#
# Lambda's ListResources payload omits Runtime entirely, so these functions are
# also the only end-to-end proof that the enricher's hydrateIfMissing call
# fires. Without it every one of them emits nothing.
#
# Three resolvable and two undecidable, deliberately: a test that asserted only
# the resolvable ones could not tell correct resolution apart from a decoder
# that emits for every runtime it sees.
#
#   java21      -> oracle:openjdk:21
#   ruby3.2     -> ruby-lang:ruby:3.2
#   dotnet8     -> microsoft:.net:8      (a product name containing a dot —
#                                         the most likely to break the CPE
#                                         shape guard's key regex enforces)
#   python3.12  -> nothing  ("python" has several live vendors, so a
#                            minor-only version is undecidable; rule 3 drops it)
#   nodejs20.x  -> nothing  (".x" is not a resolvable version)
# ===========================================================================
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

locals {
  # handler spelling per runtime; Lambda validates the format, not the contents
  lambda_runtimes = {
    java   = { runtime = "java21", handler = "example.Handler::handleRequest" }
    ruby   = { runtime = "ruby3.2", handler = "index.handler" }
    dotnet = { runtime = "dotnet8", handler = "Assembly::Namespace.Class::Method" }
    python = { runtime = "python3.12", handler = "index.handler" }
    node   = { runtime = "nodejs20.x", handler = "index.handler" }
  }
}

resource "aws_lambda_function" "runtime" {
  for_each = local.lambda_runtimes

  filename         = data.archive_file.stub.output_path
  function_name    = "${local.prefix}-${each.key}"
  role             = aws_iam_role.lambda.arn
  handler          = each.value.handler
  runtime          = each.value.runtime
  source_code_hash = data.archive_file.stub.output_base64sha256
}
