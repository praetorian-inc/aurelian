# IAM CreatePolicyVersion Privilege Escalation Scenario
# This creates a vulnerable scenario where a user can escalate privileges
# by creating a new version of an existing policy with elevated permissions

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

# Create a target policy that the vulnerable user can modify
# This policy initially has limited permissions
resource "aws_iam_policy" "vuln_createpolicyversion_target_policy" {
  name        = "vuln-iam-createpolicyversion-target-policy-${var.random_suffix}"
  description = "Target policy that can be modified via CreatePolicyVersion"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "arn:aws:s3:::example-bucket/*"
      }
    ]
  })
}

# Create a vulnerable user with CreatePolicyVersion permission
resource "aws_iam_user" "vuln_createpolicyversion_user" {
  name          = "vuln-iam-createpolicyversion-user-${var.random_suffix}"
  force_destroy = true
}

# Create a policy that allows the user to create policy versions
# This is the vulnerable permission that allows privilege escalation
resource "aws_iam_policy" "vuln_createpolicyversion_policy" {
  name = "vuln-iam-createpolicyversion-policy-${var.random_suffix}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicyVersions",
          "iam:ListPolicies"
        ]
        Resource = [
          aws_iam_policy.vuln_createpolicyversion_target_policy.arn
        ]
      }
    ]
  })
}

# Attach the policy to the vulnerable user
resource "aws_iam_user_policy_attachment" "vuln_createpolicyversion_user_policy" {
  user       = aws_iam_user.vuln_createpolicyversion_user.name
  policy_arn = aws_iam_policy.vuln_createpolicyversion_policy.arn
}

# Attach the target policy to the user so they can benefit from escalating it
resource "aws_iam_user_policy_attachment" "vuln_createpolicyversion_target_attach" {
  user       = aws_iam_user.vuln_createpolicyversion_user.name
  policy_arn = aws_iam_policy.vuln_createpolicyversion_target_policy.arn
}

# Output the resources for testing
output "vulnerable_user_name" {
  value = aws_iam_user.vuln_createpolicyversion_user.name
}

output "target_policy_arn" {
  value = aws_iam_policy.vuln_createpolicyversion_target_policy.arn
}

output "target_policy_name" {
  value = aws_iam_policy.vuln_createpolicyversion_target_policy.name
}

output "vulnerable_policy_arn" {
  value = aws_iam_policy.vuln_createpolicyversion_policy.arn
}

# Create an example administrator policy document for testing
# This represents what an attacker would use to escalate privileges
locals {
  administrator_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  }
}

output "example_administrator_policy" {
  value       = jsonencode(local.administrator_policy)
  description = "Example administrator policy that could be used for privilege escalation"
}