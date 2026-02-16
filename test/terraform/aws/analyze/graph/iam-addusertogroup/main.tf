// main.tf

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

// Create a privileged group with admin permissions
resource "aws_iam_group" "vuln_add_user_to_group_admin_group" {
  name = "vuln-iam-add-user-to-group-admin-group-${var.random_suffix}"
  path = "/groups/"
}

// Attach an administrator policy to the privileged group
resource "aws_iam_group_policy_attachment" "vuln_add_user_to_group_admin_attach" {
  group      = aws_iam_group.vuln_add_user_to_group_admin_group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

// Create a target user that can be added to the group
resource "aws_iam_user" "vuln_add_user_to_group_target" {
  name          = "vuln-iam-add-user-to-group-target-${var.random_suffix}"
  force_destroy = true
  path          = "/users/"

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Create login profile for the target user
resource "aws_iam_user_login_profile" "vuln_add_user_to_group_target_login" {
  user                    = aws_iam_user.vuln_add_user_to_group_target.name
  password_length         = 20
  password_reset_required = false

  lifecycle {
    ignore_changes = [
      password_length,
      password_reset_required
    ]
  }
}

// Create a basic policy for the target user
resource "aws_iam_policy" "vuln_add_user_to_group_target_policy" {
  name        = "vuln-iam-add-user-to-group-target-policy-${var.random_suffix}"
  description = "Basic policy for the target user"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
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

// Attach the basic policy to the target user
resource "aws_iam_user_policy_attachment" "vuln_add_user_to_group_target_attach" {
  user       = aws_iam_user.vuln_add_user_to_group_target.name
  policy_arn = aws_iam_policy.vuln_add_user_to_group_target_policy.arn
}

// Get current account ID
data "aws_caller_identity" "current" {}

// Create an attacker role with permissions to add users to groups
resource "aws_iam_role" "vuln_add_user_to_group_attacker" {
  name = "vuln-iam-add-user-to-group-attacker-${var.random_suffix}"

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

// Create a policy allowing the attacker to add users to groups
resource "aws_iam_policy" "vuln_add_user_to_group_permission_policy" {
  name        = "vuln-iam-add-user-to-group-permission-policy-${var.random_suffix}"
  description = "Policy that allows adding users to groups"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:AddUserToGroup",
          "iam:ListGroups",
          "iam:GetGroup",
          "iam:ListGroupPolicies",
          "iam:GetGroupPolicy",
          "iam:ListAttachedGroupPolicies",
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
resource "aws_iam_role_policy_attachment" "vuln_add_user_to_group_permission_attach" {
  role       = aws_iam_role.vuln_add_user_to_group_attacker.name
  policy_arn = aws_iam_policy.vuln_add_user_to_group_permission_policy.arn
}

// Output variables
output "vuln_add_user_to_group_attacker_role" {
  value       = aws_iam_role.vuln_add_user_to_group_attacker.name
  description = "Name of the attacker role with AddUserToGroup permissions"
}

output "vuln_add_user_to_group_attacker_role_arn" {
  value       = aws_iam_role.vuln_add_user_to_group_attacker.arn
  description = "ARN of the attacker role"
}

output "vuln_add_user_to_group_target_username" {
  value       = aws_iam_user.vuln_add_user_to_group_target.name
  description = "Username of the target user"
}

output "vuln_add_user_to_group_target_password" {
  value       = aws_iam_user_login_profile.vuln_add_user_to_group_target_login.password
  description = "Initial password for the target user"
  sensitive   = true
}

output "vuln_add_user_to_group_admin_group_name" {
  value       = aws_iam_group.vuln_add_user_to_group_admin_group.name
  description = "Name of the admin group that can be exploited"
}

output "exploit_command" {
  value       = "aws iam add-user-to-group --group-name ${aws_iam_group.vuln_add_user_to_group_admin_group.name} --user-name ${aws_iam_user.vuln_add_user_to_group_target.name}"
  description = "Command to exploit the vulnerability by adding the target user to the admin group"
}