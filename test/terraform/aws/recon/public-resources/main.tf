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

variable "region" {
  default = "us-east-1"
}

resource "random_id" "run" {
  byte_length = 4
}

locals {
  prefix    = "aurelian-pub-test-${random_id.run.hex}"
  os_prefix = "aur-pt-${random_id.run.hex}"
}

# ============================================================
# S3 bucket with public policy (policy-based detection)
# ============================================================
resource "aws_s3_bucket" "public" {
  bucket = "${local.prefix}-public-bucket"
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket = aws_s3_bucket.public.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public" {
  bucket = aws_s3_bucket.public.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public.arn}/*"
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.public]
}

# Private S3 bucket (should NOT appear in results)
resource "aws_s3_bucket" "private" {
  bucket = "${local.prefix}-private-bucket"
}

# ============================================================
# SNS topic with public policy (policy-based detection)
# ============================================================
resource "aws_sns_topic" "public" {
  name = "${local.prefix}-public-topic"
}

resource "aws_sns_topic_policy" "public" {
  arn = aws_sns_topic.public.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicPublish"
      Effect    = "Allow"
      Principal = "*"
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.public.arn
    }]
  })
}

# ============================================================
# SQS queue with public policy (policy-based detection)
# ============================================================
resource "aws_sqs_queue" "public" {
  name = "${local.prefix}-public-queue"
}

resource "aws_sqs_queue_policy" "public" {
  queue_url = aws_sqs_queue.public.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicSend"
      Effect    = "Allow"
      Principal = "*"
      Action    = "SQS:SendMessage"
      Resource  = aws_sqs_queue.public.arn
    }]
  })
}

# ============================================================
# Lambda shared resources
# ============================================================
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

# ============================================================
# Lambda: function URL only (AuthType=NONE, no public resource policy)
# Detected via FunctionUrlAuthType property check only.
# ============================================================
resource "aws_lambda_function" "public" {
  filename         = data.archive_file.dummy.output_path
  function_name    = "${local.prefix}-public-function"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy.output_base64sha256
}

resource "aws_lambda_function_url" "public" {
  function_name      = aws_lambda_function.public.function_name
  authorization_type = "NONE"
}

# ============================================================
# Lambda: public resource policy + AuthType=NONE function URL
# Both findings should be reported and merged. This is the
# scenario that was broken before the evaluateLambdaAccess fix.
# ============================================================
resource "aws_lambda_function" "public_policy_and_url" {
  filename         = data.archive_file.dummy.output_path
  function_name    = "${local.prefix}-policy-url-fn"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy.output_base64sha256
}

resource "aws_lambda_permission" "public_policy_and_url" {
  statement_id  = "AllowPublicInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.public_policy_and_url.function_name
  principal     = "*"
}

resource "aws_lambda_function_url" "public_policy_and_url" {
  function_name      = aws_lambda_function.public_policy_and_url.function_name
  authorization_type = "NONE"
}

# ============================================================
# Lambda: public resource policy only (no function URL)
# Detected via resource policy evaluation only.
# ============================================================
resource "aws_lambda_function" "public_policy_only" {
  filename         = data.archive_file.dummy.output_path
  function_name    = "${local.prefix}-policy-only-fn"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy.output_base64sha256
}

resource "aws_lambda_permission" "public_policy_only" {
  statement_id  = "AllowPublicInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.public_policy_only.function_name
  principal     = "*"
}

# ============================================================
# Lambda: private (AuthType=AWS_IAM, no public resource policy)
# Should NOT appear in results.
# ============================================================
resource "aws_lambda_function" "private" {
  filename         = data.archive_file.dummy.output_path
  function_name    = "${local.prefix}-private-function"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy.output_base64sha256
}

resource "aws_lambda_function_url" "private" {
  function_name      = aws_lambda_function.private.function_name
  authorization_type = "AWS_IAM"
}

# ============================================================
# EC2 instance with public IP (property-based detection)
# ============================================================
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.prefix}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.region}a"

  tags = {
    Name = "${local.prefix}-public-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${local.prefix}-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "ec2" {
  name_prefix = "${local.prefix}-ec2-sg"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.prefix}-ec2-sg"
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "public" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ec2.id]
  associate_public_ip_address = true

  tags = {
    Name = "${local.prefix}-public-instance"
  }
}

# ============================================================
# EFS file system with public policy (policy-based detection)
# ============================================================
resource "aws_efs_file_system" "public" {
  creation_token = "${local.prefix}-public-efs"

  tags = {
    Name = "${local.prefix}-public-efs"
  }
}

resource "aws_efs_file_system_policy" "public" {
  file_system_id = aws_efs_file_system.public.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicMount"
      Effect    = "Allow"
      Principal = "*"
      Action = [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite"
      ]
      Resource = aws_efs_file_system.public.arn
    }]
  })
}

# ============================================================
# Cognito user pool with self-signup (property-based detection)
# ============================================================
resource "aws_cognito_user_pool" "public" {
  name = "${local.prefix}-public-pool"

  admin_create_user_config {
    allow_admin_create_user_only = false
  }

  password_policy {
    minimum_length    = 8
    require_lowercase = false
    require_numbers   = false
    require_symbols   = false
    require_uppercase = false
  }
}

resource "aws_cognito_user_pool_domain" "public" {
  domain       = "${local.prefix}-auth"
  user_pool_id = aws_cognito_user_pool.public.id
}

# ============================================================
# RDS instance with public access (property-based detection)
# ============================================================
resource "aws_db_subnet_group" "public" {
  name       = "${local.prefix}-db-subnet"
  subnet_ids = [aws_subnet.public.id, aws_subnet.public_b.id]

  tags = {
    Name = "${local.prefix}-db-subnet"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.region}b"

  tags = {
    Name = "${local.prefix}-public-subnet-b"
  }
}

resource "aws_security_group" "rds" {
  name_prefix = "${local.prefix}-rds-sg"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.prefix}-rds-sg"
  }
}

resource "aws_db_instance" "public" {
  identifier     = "${local.prefix}-public-db"
  engine         = "postgres"
  engine_version = "16"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_type      = "gp3"

  db_name  = "testdb"
  username = "testadmin"
  password = "testpassword123!"

  publicly_accessible    = true
  db_subnet_group_name   = aws_db_subnet_group.public.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  skip_final_snapshot = true

  tags = {
    Name = "${local.prefix}-public-db"
  }
}

# ============================================================
# OpenSearch domain with public policy (policy-based detection)
# ============================================================
resource "aws_opensearch_domain" "public" {
  domain_name    = "${local.os_prefix}-os"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
    volume_type = "gp3"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true

    master_user_options {
      master_user_name     = "admin"
      master_user_password = "TestPassword1!"
    }
  }

  node_to_node_encryption {
    enabled = true
  }

  encrypt_at_rest {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "es:ESHttpGet"
      Resource  = "arn:aws:es:${var.region}:*:domain/${local.os_prefix}-os/*"
    }]
  })

  tags = {
    Name = "${local.os_prefix}-os"
  }
}
