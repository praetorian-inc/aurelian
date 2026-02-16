// main.tf

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

// Create a target user
resource "aws_iam_user" "vuln_put_group_policy_target" {
  name          = "vuln-iam-put-group-policy-target-${var.random_suffix}"
  force_destroy = true
  path          = "/users/"

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Create a login profile for the target user
resource "aws_iam_user_login_profile" "vuln_put_group_policy_target_login" {
  user                    = aws_iam_user.vuln_put_group_policy_target.name
  password_length         = 20
  password_reset_required = false

  lifecycle {
    ignore_changes = [
      password_length,
      password_reset_required
    ]
  }
}

// Create a group that the target user will be a member of
resource "aws_iam_group" "vuln_put_group_policy_group" {
  name = "vuln-iam-put-group-policy-group-${var.random_suffix}"
  path = "/groups/"
}

// Add the target user to the group
resource "aws_iam_user_group_membership" "vuln_put_group_policy_membership" {
  user = aws_iam_user.vuln_put_group_policy_target.name
  groups = [
    aws_iam_group.vuln_put_group_policy_group.name
  ]
}

// Attach basic permissions to the group
resource "aws_iam_group_policy" "vuln_put_group_policy_basic_perms" {
  name  = "vuln-iam-put-group-policy-basic-perms-${var.random_suffix}"
  group = aws_iam_group.vuln_put_group_policy_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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

// Get current account ID
data "aws_caller_identity" "current" {}

// Create an attacker role with permissions to put group policies
resource "aws_iam_role" "vuln_put_group_policy_attacker" {
  name = "vuln-iam-put-group-policy-attacker-${var.random_suffix}"

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

// Create a policy allowing the attacker to put group policies
resource "aws_iam_policy" "vuln_put_group_policy_permission_policy" {
  name        = "vuln-iam-put-group-policy-permission-policy-${var.random_suffix}"
  description = "Policy that allows putting inline policies on groups"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:PutGroupPolicy",
          "iam:ListGroups",
          "iam:GetGroup",
          "iam:ListGroupPolicies",
          "iam:GetGroupPolicy"
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
resource "aws_iam_role_policy_attachment" "vuln_put_group_policy_permission_attach" {
  role       = aws_iam_role.vuln_put_group_policy_attacker.name
  policy_arn = aws_iam_policy.vuln_put_group_policy_permission_policy.arn
}

// Create a local file with admin policy for exploitation
resource "local_file" "admin_policy" {
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
  filename = "${path.module}/admin_policy.json"
}

// Output variables
output "vuln_put_group_policy_attacker_role" {
  value       = aws_iam_role.vuln_put_group_policy_attacker.name
  description = "Name of the attacker role with PutGroupPolicy permissions"
}

output "vuln_put_group_policy_attacker_role_arn" {
  value       = aws_iam_role.vuln_put_group_policy_attacker.arn
  description = "ARN of the attacker role"
}

output "vuln_put_group_policy_target_username" {
  value       = aws_iam_user.vuln_put_group_policy_target.name
  description = "Username of the target user who is a member of the vulnerable group"
}

output "vuln_put_group_policy_target_password" {
  value       = aws_iam_user_login_profile.vuln_put_group_policy_target_login.password
  description = "Initial password for the target user"
  sensitive   = true
}

output "vuln_put_group_policy_group_name" {
  value       = aws_iam_group.vuln_put_group_policy_group.name
  description = "Name of the group that can be exploited"
}

output "admin_policy_path" {
  value       = local_file.admin_policy.filename
  description = "Path to the admin policy JSON file for exploitation"
}

output "exploit_command" {
  value       = "aws iam put-group-policy --group-name ${aws_iam_group.vuln_put_group_policy_group.name} --policy-name AdminAccess --policy-document file://admin_policy.json"
  description = "Command to exploit the vulnerability by adding an admin policy to the group"
}