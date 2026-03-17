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
    null = {
      source  = "hashicorp/null"
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

locals {
  prefix = "aurelian-ecr-${random_id.run.hex}"
  # Intentionally fake credentials used only for secret-detection testing.
  fake_aws_key    = "AKIAIOSFODNN7EXAMPLE"
  fake_aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ============================================================
# 1. ECR repo WITH an image containing a planted secret
# ============================================================
resource "aws_ecr_repository" "with_secret" {
  name                 = "${local.prefix}-secret-repo"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
}

# Build and push a minimal container image with a planted secret.
# Uses a scratch Dockerfile with a config.txt containing fake creds.
resource "null_resource" "push_image" {
  depends_on = [aws_ecr_repository.with_secret]

  provisioner "local-exec" {
    command = <<-CMD
      set -e

      REGION="${var.region}"
      REPO_URI="${aws_ecr_repository.with_secret.repository_url}"

      # Authenticate Docker to ECR
      aws ecr get-login-password --region "$REGION" | \
        docker login --username AWS --password-stdin "$REPO_URI"

      # Create a temp build context with a planted secret
      TMPDIR=$(mktemp -d)
      cat > "$TMPDIR/config.txt" <<'SECRETEOF'
      # Application Configuration
      AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
      AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      DATABASE_URL=postgres://admin:supersecret@db.internal:5432/app
SECRETEOF

      cat > "$TMPDIR/Dockerfile" <<'DOCKERFILE'
      FROM alpine:3.19
      RUN mkdir -p /app
      COPY config.txt /app/config.txt
      CMD ["cat", "/app/config.txt"]
DOCKERFILE

      # Build and push
      docker build -t "$REPO_URI:latest" "$TMPDIR"
      docker push "$REPO_URI:latest"

      # Cleanup
      rm -rf "$TMPDIR"
    CMD
  }
}

# ============================================================
# 2. ECR repo WITHOUT any images (empty registry test)
# ============================================================
resource "aws_ecr_repository" "empty" {
  name                 = "${local.prefix}-empty-repo"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
}
