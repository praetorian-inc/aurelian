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

data "aws_caller_identity" "current" {}

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
# Public AMI (property-based detection via EC2ImageEnumerator)
# ============================================================
resource "aws_ec2_image_block_public_access" "unblock" {
  state = "unblocked"
}

resource "aws_ami_copy" "public" {
  name              = "${local.prefix}-public-ami"
  description       = "Public AMI for public-resources integration test"
  source_ami_id     = data.aws_ami.amazon_linux.id
  source_ami_region = var.region

  tags = { Name = "${local.prefix}-public-ami" }

  lifecycle { ignore_changes = [deprecation_time] }
}

resource "aws_ami_launch_permission" "public" {
  image_id   = aws_ami_copy.public.id
  group      = "all"
  depends_on = [aws_ec2_image_block_public_access.unblock]
}

# ============================================================
# Amplify app with branch (property-based detection via URLs)
# ============================================================
resource "aws_amplify_app" "public" {
  name = "${local.prefix}-amplify-app"
}

resource "aws_amplify_branch" "main" {
  app_id      = aws_amplify_app.public.id
  branch_name = "main"
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

# ============================================================
# APPLICATION INGRESS LAYER (feat/public-resources-ingress)
# Cheap tranche below is always deployed. Slow/expensive resources
# (EKS, FGAC-off OpenSearch, Elastic Beanstalk) are gated behind
# var.deploy_expensive (default false) to keep the default run fast.
# ============================================================

variable "deploy_expensive" {
  description = "Deploy slow/costly fixtures (EKS, extra OpenSearch domain, Beanstalk)."
  type        = bool
  default     = false
}

# --- ELBv2: internet-facing ALB (positive) + internal ALB (negative) ---
resource "aws_lb" "public" {
  name               = "${local.os_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ec2.id]
  subnets            = [aws_subnet.public.id, aws_subnet.public_b.id]
}

resource "aws_lb" "internal" {
  name               = "${local.os_prefix}-ialb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ec2.id]
  subnets            = [aws_subnet.public.id, aws_subnet.public_b.id]
}

# --- App Runner: public ingress (positive) ---
resource "aws_apprunner_service" "public" {
  service_name = "${local.os_prefix}-apprunner"

  source_configuration {
    auto_deployments_enabled = false
    image_repository {
      image_identifier      = "public.ecr.aws/aws-containers/hello-app-runner:latest"
      image_repository_type = "ECR_PUBLIC"
      image_configuration {
        port = "8000"
      }
    }
  }

  network_configuration {
    ingress_configuration {
      is_publicly_accessible = true
    }
  }
}

# --- CloudFront: enabled distribution (positive) ---
resource "aws_cloudfront_distribution" "public" {
  enabled = true

  origin {
    domain_name = "example.com"
    origin_id   = "primary"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "primary"
    viewer_protocol_policy = "allow-all"
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# --- Global Accelerator: enabled (positive) ---
resource "aws_globalaccelerator_accelerator" "public" {
  name    = "${local.os_prefix}-ga"
  enabled = true
}

# --- Transfer Family: PUBLIC SFTP endpoint (positive) ---
resource "aws_transfer_server" "public" {
  endpoint_type          = "PUBLIC"
  protocols              = ["SFTP"]
  identity_provider_type = "SERVICE_MANAGED"

  tags = {
    Name = "${local.os_prefix}-transfer"
  }
}

# --- AppSync: API_KEY auth (positive) + AWS_IAM auth (negative) ---
resource "aws_appsync_graphql_api" "apikey" {
  name                = "${local.os_prefix}-appsync-key"
  authentication_type = "API_KEY"
  schema              = "type Query { hello: String }"
}

resource "aws_appsync_graphql_api" "iam" {
  name                = "${local.os_prefix}-appsync-iam"
  authentication_type = "AWS_IAM"
  schema              = "type Query { hello: String }"
}

# --- API Gateway REST: NONE-auth method (positive) ---
resource "aws_api_gateway_rest_api" "public" {
  name = "${local.os_prefix}-rest"
}

resource "aws_api_gateway_resource" "public" {
  rest_api_id = aws_api_gateway_rest_api.public.id
  parent_id   = aws_api_gateway_rest_api.public.root_resource_id
  path_part   = "public"
}

resource "aws_api_gateway_method" "public" {
  rest_api_id   = aws_api_gateway_rest_api.public.id
  resource_id   = aws_api_gateway_resource.public.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "public" {
  rest_api_id = aws_api_gateway_rest_api.public.id
  resource_id = aws_api_gateway_resource.public.id
  http_method = aws_api_gateway_method.public.http_method
  type        = "MOCK"
}

# --- API Gateway HTTP: NONE-auth route (positive) ---
resource "aws_apigatewayv2_api" "public" {
  name          = "${local.os_prefix}-http"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_route" "public" {
  api_id    = aws_apigatewayv2_api.public.id
  route_key = "GET /public"
}

# --- API Gateway REST: PRIVATE endpoint + NONE-auth method (negative) ---
# A PRIVATE REST API is reachable only from within the VPC via an interface
# endpoint, so its NONE-auth method is not internet-exposed. The evaluator skips
# PRIVATE APIs before counting unauthenticated methods, so this must NOT flag.
resource "aws_api_gateway_rest_api" "private" {
  name = "${local.os_prefix}-rest-priv"

  endpoint_configuration {
    types = ["PRIVATE"]
  }
}

resource "aws_api_gateway_resource" "private" {
  rest_api_id = aws_api_gateway_rest_api.private.id
  parent_id   = aws_api_gateway_rest_api.private.root_resource_id
  path_part   = "private"
}

resource "aws_api_gateway_method" "private" {
  rest_api_id   = aws_api_gateway_rest_api.private.id
  resource_id   = aws_api_gateway_resource.private.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "private" {
  rest_api_id = aws_api_gateway_rest_api.private.id
  resource_id = aws_api_gateway_resource.private.id
  http_method = aws_api_gateway_method.private.http_method
  type        = "MOCK"
}

# --- API Gateway REST: NONE-auth method + resource policy (positive, triage) ---
# A resource policy can restrict invocation (source IP, VPC endpoint, account)
# independently of method authorization, so the evaluator reports for triage with
# a policy-specific reason rather than asserting public. Still flagged.
resource "aws_api_gateway_rest_api" "policy" {
  name = "${local.os_prefix}-rest-pol"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "execute-api:Invoke"
      Resource  = "execute-api:/*"
      Condition = {
        IpAddress = { "aws:SourceIp" = "10.0.0.0/8" }
      }
    }]
  })
}

resource "aws_api_gateway_resource" "policy" {
  rest_api_id = aws_api_gateway_rest_api.policy.id
  parent_id   = aws_api_gateway_rest_api.policy.root_resource_id
  path_part   = "policy"
}

resource "aws_api_gateway_method" "policy" {
  rest_api_id   = aws_api_gateway_rest_api.policy.id
  resource_id   = aws_api_gateway_resource.policy.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "policy" {
  rest_api_id = aws_api_gateway_rest_api.policy.id
  resource_id = aws_api_gateway_resource.policy.id
  http_method = aws_api_gateway_method.policy.http_method
  type        = "MOCK"
}

# --- AppSync: AWS_IAM primary + additional API_KEY provider (positive) ---
# A non-API_KEY primary auth type does not preclude an additional API_KEY
# provider; any holder of an API key can call the full schema, so this flags.
resource "aws_appsync_graphql_api" "additional_apikey" {
  name                = "${local.os_prefix}-appsync-addl"
  authentication_type = "AWS_IAM"
  schema              = "type Query { hello: String }"

  additional_authentication_provider {
    authentication_type = "API_KEY"
  }
}

# ============================================================
# Expensive / slow fixtures (var.deploy_expensive)
# ============================================================

# --- OpenSearch: FGAC-OFF domain (positive); the FGAC-ON domain above is the negative ---
resource "aws_opensearch_domain" "no_fgac" {
  count          = var.deploy_expensive ? 1 : 0
  domain_name    = "${local.os_prefix}-nofgac"
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

  # Wildcard ("*") principal — what the evaluator flags. AWS rejects a fully
  # open FGAC-off public domain, so an IpAddress condition is attached to make
  # the policy "restrictive" enough to create. The evaluator inspects only the
  # principal (conditions are a known follow-up), so this still flags as public.
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "es:ESHttpGet"
      Resource  = "arn:aws:es:${var.region}:*:domain/${local.os_prefix}-nofgac/*"
      Condition = {
        IpAddress = { "aws:SourceIp" = "3.0.0.0/8" }
      }
    }]
  })

  tags = {
    Name = "${local.os_prefix}-nofgac"
  }
}

# --- OpenSearch: FGAC-OFF + restrictive (non-wildcard) policy (negative) ---
# With FGAC disabled the access policy is the only authorization layer. A policy
# scoped to a specific principal still gates the domain, so it must NOT flag —
# only a wildcard-principal policy does. Mirror of the no_fgac positive above.
resource "aws_opensearch_domain" "no_fgac_restrictive" {
  count          = var.deploy_expensive ? 1 : 0
  domain_name    = "${local.os_prefix}-nofgacr"
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

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "es:ESHttpGet"
      Resource  = "arn:aws:es:${var.region}:*:domain/${local.os_prefix}-nofgacr/*"
    }]
  })

  tags = {
    Name = "${local.os_prefix}-nofgacr"
  }
}

# --- EKS: public endpoint open to 0.0.0.0/0 (positive) ---
resource "aws_iam_role" "eks" {
  count = var.deploy_expensive ? 1 : 0
  name  = "${local.os_prefix}-eks-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  count      = var.deploy_expensive ? 1 : 0
  role       = aws_iam_role.eks[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "public" {
  count    = var.deploy_expensive ? 1 : 0
  name     = "${local.os_prefix}-eks"
  role_arn = aws_iam_role.eks[0].arn

  vpc_config {
    subnet_ids              = [aws_subnet.public.id, aws_subnet.public_b.id]
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster]
}

# --- Elastic Beanstalk: public environment (positive) ---
data "aws_elastic_beanstalk_solution_stack" "python" {
  count       = var.deploy_expensive ? 1 : 0
  most_recent = true
  name_regex  = "^64bit Amazon Linux 2023 (.*) running Python (.*)$"
}

resource "aws_iam_role" "beanstalk_ec2" {
  count = var.deploy_expensive ? 1 : 0
  name  = "${local.os_prefix}-eb-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "beanstalk_web" {
  count      = var.deploy_expensive ? 1 : 0
  role       = aws_iam_role.beanstalk_ec2[0].name
  policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
}

resource "aws_iam_instance_profile" "beanstalk_ec2" {
  count = var.deploy_expensive ? 1 : 0
  name  = "${local.os_prefix}-eb-profile"
  role  = aws_iam_role.beanstalk_ec2[0].name
}

resource "aws_elastic_beanstalk_application" "public" {
  count = var.deploy_expensive ? 1 : 0
  name  = "${local.os_prefix}-eb"
}

resource "aws_elastic_beanstalk_environment" "public" {
  count               = var.deploy_expensive ? 1 : 0
  name                = "${local.os_prefix}-env"
  application         = aws_elastic_beanstalk_application.public[0].name
  solution_stack_name = data.aws_elastic_beanstalk_solution_stack.python[0].name

  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = aws_iam_instance_profile.beanstalk_ec2[0].name
  }

  setting {
    namespace = "aws:ec2:vpc"
    name      = "VPCId"
    value     = aws_vpc.main.id
  }

  setting {
    namespace = "aws:ec2:vpc"
    name      = "Subnets"
    value     = aws_subnet.public.id
  }

  setting {
    namespace = "aws:ec2:vpc"
    name      = "AssociatePublicIpAddress"
    value     = "true"
  }
}
