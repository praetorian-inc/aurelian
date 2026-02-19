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
    # Configured via -backend-config at init time
  }
}

provider "aws" {
  region = var.region
}

resource "random_id" "run" {
  byte_length = 4
}

locals {
  prefix = "aurelian-test-${random_id.run.hex}"
}

# Healthy distribution: S3 bucket origin that remains intact (false positive guard)
resource "aws_s3_bucket" "healthy" {
  bucket        = "${local.prefix}-healthy-bucket"
  force_destroy = true
}

resource "aws_cloudfront_origin_access_identity" "healthy" {
  comment = "OAI for ${local.prefix}-healthy-bucket"
}

resource "aws_cloudfront_distribution" "healthy" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  comment             = "${local.prefix} healthy distribution"

  origin {
    domain_name = aws_s3_bucket.healthy.bucket_regional_domain_name
    origin_id   = "S3-${local.prefix}-healthy"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.healthy.cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${local.prefix}-healthy"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  price_class = "PriceClass_100"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "${local.prefix}-healthy"
  }
}

# Vulnerable distribution: S3 bucket origin that will be deleted mid-test.
# force_destroy + lifecycle ignore allow terraform destroy to succeed even
# after the bucket is manually deleted during testing.
resource "aws_s3_bucket" "vulnerable" {
  bucket        = "${local.prefix}-vuln-bucket"
  force_destroy = true

  lifecycle {
    ignore_changes = all
  }
}

resource "aws_cloudfront_origin_access_identity" "vulnerable" {
  comment = "OAI for ${local.prefix}-vuln-bucket"
}

resource "aws_cloudfront_distribution" "vulnerable" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  comment             = "${local.prefix} vulnerable distribution"

  origin {
    domain_name = aws_s3_bucket.vulnerable.bucket_regional_domain_name
    origin_id   = "S3-${local.prefix}-vulnerable"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.vulnerable.cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${local.prefix}-vulnerable"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  price_class = "PriceClass_100"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "${local.prefix}-vulnerable"
  }
}
