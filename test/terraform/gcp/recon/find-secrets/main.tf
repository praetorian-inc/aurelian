// Module: gcp-recon-find-secrets
// Provisions GCP resources with intentionally hardcoded secrets for
// integration testing the find-secrets module.
//
// ==================== TEST CASES ====================
//
// | #  | Resource Name                       | GCP Resource Type                      | Secret Location        |
// |----|--------------------------------------|----------------------------------------|------------------------|
// | 1  | ${prefix}-secret-vm                  | compute.googleapis.com/Instance        | startup-script metadata|
// | 2  | ${prefix}-secret-fn                  | cloudfunctions.googleapis.com/Function | source code            |
// | 3  | ${prefix}-secret-run                 | run.googleapis.com/Service             | environment variables  |
// | 4  | ${prefix}-secret-bucket              | storage.googleapis.com/Bucket          | object content         |

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
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

  backend "s3" {}
}

provider "google" {
  region = var.region
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  prefix = "aur-sec-${random_string.suffix.result}"
  labels = {
    managed-by = "terraform"
    purpose    = "aurelian-gcp-find-secrets-testing"
  }
  # Intentionally fake credentials used only for secret-detection testing.
  fake_aws_key    = "AKIAIOSFODNN7EXAMPLE"
  fake_aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

data "google_project" "current" {}

#==============================================================================
# RESOURCE 1: Compute Instance with secret in startup script
#==============================================================================
resource "google_compute_instance" "with_secret" {
  name         = "${local.prefix}-secret-vm"
  machine_type = "e2-micro"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
  }

  metadata = {
    startup-script = <<-EOF
      #!/bin/bash
      export AWS_ACCESS_KEY_ID="${local.fake_aws_key}"
      export AWS_SECRET_ACCESS_KEY="${local.fake_aws_secret}"
      echo "configured"
    EOF
  }

  labels = local.labels
}

#==============================================================================
# RESOURCE 2: Cloud Function with secret in source code
#==============================================================================
resource "google_storage_bucket" "function_source" {
  name          = "${local.prefix}-fn-src"
  location      = var.region
  labels        = local.labels
  force_destroy = true
}

data "archive_file" "function_with_secret" {
  type        = "zip"
  output_path = "${path.module}/function_secret.zip"

  source {
    content  = <<-PYEOF
      import os
      def hello_http(request):
          api_key = "AKIAIOSFODNN7EXAMPLE"
          secret  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
          return "Hello World!"
    PYEOF
    filename = "main.py"
  }
}

resource "google_storage_bucket_object" "function_source" {
  name   = "function-secret-${data.archive_file.function_with_secret.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.function_with_secret.output_path
}

resource "google_cloudfunctions_function" "with_secret" {
  name                  = "${local.prefix}-secret-fn"
  runtime               = "python312"
  entry_point           = "hello_http"
  trigger_http          = true
  available_memory_mb   = 128
  source_archive_bucket = google_storage_bucket.function_source.name
  source_archive_object = google_storage_bucket_object.function_source.name
  labels                = local.labels
}

#==============================================================================
# RESOURCE 3: Cloud Run Service with secret in environment variable
#==============================================================================
resource "google_cloud_run_v2_service" "with_secret" {
  name     = "${local.prefix}-secret-run"
  location = var.region

  template {
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello:latest"

      env {
        name  = "AWS_ACCESS_KEY_ID"
        value = local.fake_aws_key
      }
      env {
        name  = "AWS_SECRET_ACCESS_KEY"
        value = local.fake_aws_secret
      }
    }
  }

  labels = local.labels
}

#==============================================================================
# RESOURCE 4: Storage Bucket with secret in object content
#==============================================================================
resource "google_storage_bucket" "with_secret" {
  name          = "${local.prefix}-secret-bucket"
  location      = var.region
  labels        = local.labels
  force_destroy = true
}

resource "google_storage_bucket_object" "secret_config" {
  name    = "config/app.env"
  bucket  = google_storage_bucket.with_secret.name
  content = <<-EOF
    AWS_ACCESS_KEY_ID=${local.fake_aws_key}
    AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}
  EOF
}
