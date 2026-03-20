// main.tf

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

// Create a high-privilege target user
resource "aws_iam_user" "vuln_create_access_key_target" {
  name          = "vuln-iam-create-access-key-target-${var.random_suffix}"
  force_destroy = true
  path          = "/users/"

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Create a high-privilege policy for the target user
resource "aws_iam_policy" "vuln_create_access_key_target_policy" {
  name        = "vuln-iam-create-access-key-target-policy-${var.random_suffix}"
  description = "Policy with elevated permissions for the target user"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "ec2:*",
          "lambda:*",
          "dynamodb:*",
          "cloudformation:*"
          // More high-privilege permissions could be added here
        ]
        Resource = "*"
      }
    ]
  })
}

// Attach the high-privilege policy to the target user
resource "aws_iam_user_policy_attachment" "vuln_create_access_key_target_attach" {
  user       = aws_iam_user.vuln_create_access_key_target.name
  policy_arn = aws_iam_policy.vuln_create_access_key_target_policy.arn
}

// Create a vulnerable user with limited permissions
resource "aws_iam_user" "vuln_create_access_key_attacker" {
  name          = "vuln-iam-create-access-key-attacker-${var.random_suffix}"
  force_destroy = true
  path          = "/users/"

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Create a policy allowing the attacker to create access keys for other users
resource "aws_iam_policy" "vuln_create_access_key_permission_policy" {
  name        = "vuln-iam-create-access-key-permission-policy-${var.random_suffix}"
  description = "Policy that allows creating access keys for other users"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:ListUsers"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation"
        ]
        Resource = "*"
      }
    ]
  })
}

// Attach the permission policy to the attacker user
resource "aws_iam_user_policy_attachment" "vuln_create_access_key_permission_attach" {
  user       = aws_iam_user.vuln_create_access_key_attacker.name
  policy_arn = aws_iam_policy.vuln_create_access_key_permission_policy.arn
}

// Create access key for attacker user (to use for the exploit)
resource "aws_iam_access_key" "vuln_create_access_key_attacker_key" {
  user = aws_iam_user.vuln_create_access_key_attacker.name
}

// Outputs
output "vuln_create_access_key_attacker_username" {
  value       = aws_iam_user.vuln_create_access_key_attacker.name
  description = "Username of the attacker with CreateAccessKey permissions"
}

output "vuln_create_access_key_target_username" {
  value       = aws_iam_user.vuln_create_access_key_target.name
  description = "Username of the target with elevated permissions"
}

output "vuln_create_access_key_attacker_access_key" {
  value       = aws_iam_access_key.vuln_create_access_key_attacker_key.id
  description = "Access key ID for the attacker user"
  sensitive   = true
}

output "vuln_create_access_key_attacker_secret_key" {
  value       = aws_iam_access_key.vuln_create_access_key_attacker_key.secret
  description = "Secret access key for the attacker user"
  sensitive   = true
}