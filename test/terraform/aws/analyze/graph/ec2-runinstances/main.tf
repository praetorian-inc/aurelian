// main.tf

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

// Create a high-privilege service role for EC2
resource "aws_iam_role" "vuln_ec2_passrole_target_role" {
  name = "vuln-ec2-passrole-target-role-${var.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
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

// Create a high-privilege policy for the target role
resource "aws_iam_policy" "vuln_ec2_passrole_target_policy" {
  name        = "vuln-ec2-passrole-target-policy-${var.random_suffix}"
  description = "Policy with elevated permissions for the target role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "dynamodb:*",
          "secretsmanager:*",
          "ssm:*",
          "lambda:*"
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

// Attach the high-privilege policy to the target role
resource "aws_iam_role_policy_attachment" "vuln_ec2_passrole_target_attach" {
  role       = aws_iam_role.vuln_ec2_passrole_target_role.name
  policy_arn = aws_iam_policy.vuln_ec2_passrole_target_policy.arn
}

// Create an instance profile for the target role
resource "aws_iam_instance_profile" "vuln_ec2_passrole_target_profile" {
  name = "vuln-ec2-passrole-target-profile-${var.random_suffix}"
  role = aws_iam_role.vuln_ec2_passrole_target_role.name

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Create an attacker user with limited permissions
resource "aws_iam_user" "vuln_ec2_passrole_attacker" {
  name          = "vuln-ec2-passrole-attacker-${var.random_suffix}"
  force_destroy = true
  path          = "/users/"

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Create a policy allowing the attacker to launch EC2 instances and pass roles
resource "aws_iam_policy" "vuln_ec2_passrole_permission_policy" {
  name        = "vuln-ec2-passrole-permission-policy-${var.random_suffix}"
  description = "Policy that allows launching EC2 instances and passing roles"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:DescribeInstances",
          "ec2:CreateTags",
          "ec2:DescribeImages",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeKeyPairs",
          "ec2:CreateKeyPair",
          "ec2:ImportKeyPair"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.vuln_ec2_passrole_target_role.arn
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

// Attach the permission policy to the attacker user
resource "aws_iam_user_policy_attachment" "vuln_ec2_passrole_permission_attach" {
  user       = aws_iam_user.vuln_ec2_passrole_attacker.name
  policy_arn = aws_iam_policy.vuln_ec2_passrole_permission_policy.arn
}

// Output variables
output "vuln_ec2_passrole_attacker_username" {
  value       = aws_iam_user.vuln_ec2_passrole_attacker.name
  description = "Username of the attacker with EC2 and PassRole permissions"
}

output "vuln_ec2_passrole_target_instance_profile" {
  value       = aws_iam_instance_profile.vuln_ec2_passrole_target_profile.name
  description = "Name of the instance profile with elevated permissions"
}

output "vuln_ec2_passrole_target_role_arn" {
  value       = aws_iam_role.vuln_ec2_passrole_target_role.arn
  description = "ARN of the target role with elevated permissions"
}