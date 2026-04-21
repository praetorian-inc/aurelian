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
    null = {
      source  = "hashicorp/null"
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

variable "region" {
  default = "us-east-1"
}

resource "random_id" "run" {
  byte_length = 4
}

locals {
  prefix = "aurelian-amplify-test-${random_id.run.hex}"

  # Fake but pattern-valid Amplify/AWS config values embedded in the deployed
  # HTML. The amplify-config module's regex extractors match these.
  expected_region              = "us-east-1"
  expected_user_pool_id        = "us-east-1_AurelianTP"
  expected_user_pool_client_id = "aurelianclient1234567890ab"
  expected_identity_pool_id    = "us-east-1:11111111-2222-3333-4444-555555555555"
  expected_appsync_endpoint    = "https://aurelianabc123def.appsync-api.us-east-1.amazonaws.com/graphql"
  expected_appsync_api_key     = "da2-aurelianaaaaaaaaaaaaaaaaaa"

  source_url = "https://${aws_s3_bucket.deploy.bucket}.s3.${var.region}.amazonaws.com/${aws_s3_object.site_zip.key}"
}

# ============================================================
# Amplify app + branches (manual-deploy platform)
# ============================================================
resource "aws_amplify_app" "test" {
  name     = "${local.prefix}-app"
  platform = "WEB"
}

resource "aws_amplify_branch" "main" {
  app_id      = aws_amplify_app.test.id
  branch_name = "main"
  stage       = "PRODUCTION"
}

resource "aws_amplify_branch" "dev" {
  app_id      = aws_amplify_app.test.id
  branch_name = "dev"
  stage       = "DEVELOPMENT"
}

# ============================================================
# Build a site zip with an index.html that embeds Amplify config
# ============================================================
data "archive_file" "site" {
  type        = "zip"
  output_path = "${path.module}/site.zip"

  source {
    filename = "index.html"
    content  = <<-HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>Aurelian Amplify Test</title>
        <script>
          var awsConfig = {
            "aws_project_region": "${local.expected_region}",
            "aws_cognito_identity_pool_id": "${local.expected_identity_pool_id}",
            "aws_user_pools_id": "${local.expected_user_pool_id}",
            "aws_user_pools_web_client_id": "${local.expected_user_pool_client_id}",
            "aws_cognito_mfa_configuration": "OPTIONAL",
            "aws_cognito_signup_attributes": ["EMAIL"],
            "aws_cognito_username_attributes": ["EMAIL"],
            "aws_appsync_graphqlEndpoint": "${local.expected_appsync_endpoint}",
            "aws_appsync_apiKey": "${local.expected_appsync_api_key}",
            "aws_appsync_authenticationType": "API_KEY"
          };
        </script>
      </head>
      <body><h1>Aurelian Amplify Test</h1></body>
      </html>
    HTML
  }
}

# ============================================================
# Public-read S3 bucket that hosts the deployment zip. Amplify's
# StartDeployment API fetches the zip from source_url at deploy time.
# ============================================================
resource "aws_s3_bucket" "deploy" {
  bucket        = "${local.prefix}-deploy"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "deploy" {
  bucket = aws_s3_bucket.deploy.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "deploy" {
  bucket                  = aws_s3_bucket.deploy.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "deploy" {
  bucket = aws_s3_bucket.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadZip"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.deploy.arn}/*"
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.deploy]
}

resource "aws_s3_object" "site_zip" {
  bucket = aws_s3_bucket.deploy.id
  key    = "site.zip"
  source = data.archive_file.site.output_path
  etag   = data.archive_file.site.output_md5
}

# ============================================================
# Deploy the zip to each branch via `aws amplify start-deployment`.
# The AWS provider has no native deployment resource, so we invoke
# the CLI and poll until the job reaches SUCCEED. Re-runs whenever
# the zip etag or set of branches changes.
# ============================================================
resource "null_resource" "deploy" {
  for_each = toset([
    aws_amplify_branch.main.branch_name,
    aws_amplify_branch.dev.branch_name,
  ])

  triggers = {
    zip_etag = aws_s3_object.site_zip.etag
    branch   = each.value
    app_id   = aws_amplify_app.test.id
  }

  provisioner "local-exec" {
    command = <<-CMD
      set -eu
      APP_ID="${aws_amplify_app.test.id}"
      BRANCH="${each.value}"
      REGION="${var.region}"
      SOURCE_URL="${local.source_url}"

      JOB_ID=$(aws amplify start-deployment \
        --region "$REGION" \
        --app-id "$APP_ID" \
        --branch-name "$BRANCH" \
        --source-url "$SOURCE_URL" \
        --query 'jobSummary.jobId' \
        --output text)
      echo "amplify deploy $BRANCH started: job=$JOB_ID"

      for _ in $(seq 1 60); do
        STATUS=$(aws amplify get-job \
          --region "$REGION" \
          --app-id "$APP_ID" \
          --branch-name "$BRANCH" \
          --job-id "$JOB_ID" \
          --query 'job.summary.status' \
          --output text)
        case "$STATUS" in
          SUCCEED)
            echo "amplify deploy $BRANCH: SUCCEED (job=$JOB_ID)"
            exit 0
            ;;
          FAILED|CANCELLED)
            echo "amplify deploy $BRANCH: $STATUS (job=$JOB_ID)" >&2
            exit 1
            ;;
        esac
        sleep 5
      done

      echo "amplify deploy $BRANCH: timed out after 5 minutes (job=$JOB_ID)" >&2
      exit 1
    CMD
  }

  depends_on = [aws_s3_bucket_policy.deploy, aws_s3_object.site_zip]
}

# ============================================================
# Outputs consumed by the Go integration tests
# ============================================================
output "app_id" {
  value = aws_amplify_app.test.id
}

output "default_domain" {
  value = aws_amplify_app.test.default_domain
}

output "main_url" {
  value = "https://${aws_amplify_branch.main.branch_name}.${aws_amplify_app.test.default_domain}"
}

output "dev_url" {
  value = "https://${aws_amplify_branch.dev.branch_name}.${aws_amplify_app.test.default_domain}"
}

output "expected_region" {
  value = local.expected_region
}

output "expected_user_pool_id" {
  value = local.expected_user_pool_id
}

output "expected_user_pool_client_id" {
  value = local.expected_user_pool_client_id
}

output "expected_identity_pool_id" {
  value = local.expected_identity_pool_id
}

output "expected_appsync_endpoint" {
  value = local.expected_appsync_endpoint
}

output "expected_appsync_api_key" {
  value = local.expected_appsync_api_key
}
