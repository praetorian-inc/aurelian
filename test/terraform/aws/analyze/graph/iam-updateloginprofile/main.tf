// main.tf

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

// Create a high-privilege target user with a login profile
resource "aws_iam_user" "vuln_update_login_profile_target" {
  name          = "vuln-iam-iam-update-login-profile-target-${var.random_suffix}"
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
resource "aws_iam_policy" "vuln_update_login_profile_target_policy" {
  name        = "vuln-iam-update-login-profile-target-policy-${var.random_suffix}"
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
          "cloudformation:*",
          "iam:Get*",
          "iam:List*"
        ]
        Resource = "*"
      }
    ]
  })

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Attach the high-privilege policy to the target user
resource "aws_iam_user_policy_attachment" "vuln_update_login_profile_target_attach" {
  user       = aws_iam_user.vuln_update_login_profile_target.name
  policy_arn = aws_iam_policy.vuln_update_login_profile_target_policy.arn
}

// Create initial login profile for the target user
resource "aws_iam_user_login_profile" "vuln_update_login_profile_target_login" {
  user                    = aws_iam_user.vuln_update_login_profile_target.name
  password_length         = 20
  password_reset_required = false

  lifecycle {
    ignore_changes = [
      password_length,
      password_reset_required
    ]
  }
}

// Get current account ID
data "aws_caller_identity" "current" {}

// Create an attacker role with limited permissions
resource "aws_iam_role" "vuln_update_login_profile_attacker" {
  name = "vuln-iam-update-login-profile-attacker-${var.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Create a policy allowing the attacker to update login profiles for other users
resource "aws_iam_policy" "vuln_update_login_profile_permission_policy" {
  name        = "vuln-iam-update-login-profile-permission-policy-${var.random_suffix}"
  description = "Policy that allows updating login profiles for other users"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:UpdateLoginProfile",
          "iam:ListUsers",
          "iam:GetUser"
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

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Attach the permission policy to the attacker role
resource "aws_iam_role_policy_attachment" "vuln_update_login_profile_permission_attach" {
  role       = aws_iam_role.vuln_update_login_profile_attacker.name
  policy_arn = aws_iam_policy.vuln_update_login_profile_permission_policy.arn
}

// Output variables
output "vuln_update_login_profile_attacker_role" {
  value       = aws_iam_role.vuln_update_login_profile_attacker.name
  description = "Name of the attacker role with UpdateLoginProfile permissions"
}

output "vuln_update_login_profile_attacker_role_arn" {
  value       = aws_iam_role.vuln_update_login_profile_attacker.arn
  description = "ARN of the attacker role"
}

output "vuln_update_login_profile_target_username" {
  value       = aws_iam_user.vuln_update_login_profile_target.name
  description = "Username of the target with elevated permissions"
}

output "vuln_update_login_profile_target_password" {
  value       = aws_iam_user_login_profile.vuln_update_login_profile_target_login.password
  description = "Initial password for the target user (will be changed by the exploit)"
  sensitive   = true
}