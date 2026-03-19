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

locals {
  prefix    = "aurelian-sdt-${random_id.run.hex}"
  zone_name = "${local.prefix}.test.example.com"

  # Unclaimed EB prefix — random hex makes collision near-impossible.
  eb_prefix = "aurelian-eb-${random_id.run.hex}-unclaimed"

  # AWS IP that is NOT an allocated EIP in the test account.
  # 3.5.140.1 is in the 3.5.140.0/22 AMAZON prefix published in ip-ranges.json.
  dangling_ip = "3.5.140.1"

  # Route53-pattern nameservers pointing to a non-existent hosted zone.
  # These match the nsRoute53Pattern regex (ns-\d+.awsdns-\d+.\w+) and resolve
  # to real Route53 DNS servers, but they will return REFUSED for our test domain
  # since no hosted zone is configured.
  fake_ns = [
    "ns-2000.awsdns-58.co.uk.",
    "ns-1000.awsdns-23.org.",
    "ns-500.awsdns-10.net.",
    "ns-100.awsdns-05.com.",
  ]
}

# ============================================================
# Public hosted zone for all test records
# ============================================================
resource "aws_route53_zone" "test" {
  name = local.zone_name

  tags = {
    Name    = local.prefix
    Purpose = "aurelian-integration-test"
  }
}

# ============================================================
# 1. EB CNAME Takeover — CNAME pointing to unclaimed EB prefix
# ============================================================
resource "aws_route53_record" "eb_cname" {
  zone_id = aws_route53_zone.test.zone_id
  name    = "eb-takeover.${local.zone_name}"
  type    = "CNAME"
  ttl     = 300
  records = ["${local.eb_prefix}.us-east-2.elasticbeanstalk.com"]
}

# ============================================================
# 2. EIP Dangling A Record — A record with AWS IP not allocated
# ============================================================
resource "aws_route53_record" "eip_dangling" {
  zone_id = aws_route53_zone.test.zone_id
  name    = "eip-dangling.${local.zone_name}"
  type    = "A"
  ttl     = 300
  records = [local.dangling_ip]
}

# ============================================================
# 3. NS Delegation Takeover — NS record to non-existent zone
# ============================================================
resource "aws_route53_record" "ns_delegation" {
  zone_id = aws_route53_zone.test.zone_id
  name    = "ns-dangling.${local.zone_name}"
  type    = "NS"
  ttl     = 300
  records = local.fake_ns
}

# ============================================================
# 4. Safe records — should NOT trigger any findings
# ============================================================

# Safe CNAME pointing to a non-EB target.
resource "aws_route53_record" "safe_cname" {
  zone_id = aws_route53_zone.test.zone_id
  name    = "safe.${local.zone_name}"
  type    = "CNAME"
  ttl     = 300
  records = ["www.example.com"]
}

# Safe A record pointing to a non-AWS private IP.
resource "aws_route53_record" "safe_a" {
  zone_id = aws_route53_zone.test.zone_id
  name    = "safe-a.${local.zone_name}"
  type    = "A"
  ttl     = 300
  records = ["192.168.1.1"]
}
