// Module: gcp-recon-list
// Enumerates GCP resources across a project.
//
// ==================== TEST CASES ====================
//
// This fixture provisions diverse GCP resources for testing both
// list-all and public-resources modules.
//
// | #  | Resource Name                 | GCP Resource Type                           | Public | Expected Result    |
// |----|-------------------------------|---------------------------------------------|--------|--------------------|
// | 1  | ${prefix}-public-bucket       | storage.googleapis.com/Bucket               | YES    | DISCOVERED + RISK  |
// | 2  | ${prefix}-private-bucket      | storage.googleapis.com/Bucket               | NO     | DISCOVERED         |
// | 3  | ${prefix}-instance            | compute.googleapis.com/Instance             | YES    | DISCOVERED + RISK  |
// | 4  | ${prefix}-sql                 | sqladmin.googleapis.com/Instance            | YES    | DISCOVERED + RISK  |
// | 5  | ${prefix}-zone                | dns.googleapis.com/ManagedZone              | NO     | DISCOVERED         |
// | 6  | ${prefix}-public-fn           | cloudfunctions.googleapis.com/Function      | YES    | DISCOVERED + RISK  |

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
  prefix = "aur-itest-${random_string.suffix.result}"
  labels = {
    managed-by = "terraform"
    purpose    = "aurelian-gcp-list-testing"
  }
}

data "google_project" "current" {}

#==============================================================================
# RESOURCE 01: Cloud Storage Bucket (public, uniform bucket-level access)
#==============================================================================
resource "google_storage_bucket" "public" {
  name                        = "${local.prefix}-public-bucket"
  location                    = var.region
  uniform_bucket_level_access = true
  labels                      = local.labels
  force_destroy               = true
}

resource "google_storage_bucket_iam_member" "public_viewer" {
  bucket = google_storage_bucket.public.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

#==============================================================================
# RESOURCE 02: Cloud Storage Bucket (private)
#==============================================================================
resource "google_storage_bucket" "private" {
  name                        = "${local.prefix}-private-bucket"
  location                    = var.region
  uniform_bucket_level_access = true
  labels                      = local.labels
  force_destroy               = true
}

#==============================================================================
# RESOURCE 03: Compute Engine Instance (with external IP)
#==============================================================================
resource "google_compute_instance" "test" {
  name         = "${local.prefix}-instance"
  machine_type = "e2-micro"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
    access_config {} # Assigns an external IP
  }

  labels = local.labels
}

#==============================================================================
# RESOURCE 04: Cloud SQL Instance (public IP enabled)
#==============================================================================
resource "google_sql_database_instance" "test" {
  name             = "${local.prefix}-sql"
  database_version = "POSTGRES_15"
  region           = var.region

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
    }
  }

  deletion_protection = false
}

#==============================================================================
# RESOURCE 05: Cloud DNS Managed Zone
#==============================================================================
resource "google_dns_managed_zone" "test" {
  name        = "${local.prefix}-zone"
  dns_name    = "${local.prefix}.example.com."
  description = "Aurelian integration test DNS zone"
  labels      = local.labels
}

#==============================================================================
# RESOURCE 06: Cloud Function (gen1, public with allUsers invoker)
#==============================================================================
resource "google_storage_bucket" "function_source" {
  name          = "${local.prefix}-fn-source"
  location      = var.region
  labels        = local.labels
  force_destroy = true
}

data "archive_file" "function" {
  type        = "zip"
  output_path = "${path.module}/function.zip"

  source {
    content  = "def hello_http(request):\n    return 'Hello World!'\n"
    filename = "main.py"
  }
}

resource "google_storage_bucket_object" "function_source" {
  name   = "function-${data.archive_file.function.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.function.output_path
}

resource "google_cloudfunctions_function" "public" {
  name                  = "${local.prefix}-public-fn"
  runtime               = "python312"
  entry_point           = "hello_http"
  trigger_http          = true
  available_memory_mb   = 128
  source_archive_bucket = google_storage_bucket.function_source.name
  source_archive_object = google_storage_bucket_object.function_source.name
  labels                = local.labels
}

resource "google_cloudfunctions_function_iam_member" "public_invoker" {
  cloud_function = google_cloudfunctions_function.public.name
  region         = var.region
  role           = "roles/cloudfunctions.invoker"
  member         = "allUsers"
}
