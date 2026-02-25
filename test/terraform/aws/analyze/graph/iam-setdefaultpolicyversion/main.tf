// main.tf

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

// Create a restricted user that has the dangerous permission
resource "aws_iam_user" "vuln_iam_setdefaultpolicyversion_user" {
  name          = "vuln-iam-setdefaultpolicyversion-user-${var.random_suffix}"
  force_destroy = true
  path          = "/users/"

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Create the initial safe policy that the vulnerable user can modify
resource "aws_iam_policy" "vuln_iam_setdefaultpolicyversion_target_policy" {
  name        = "vuln-iam-setdefaultpolicyversion-target-${var.random_suffix}"
  description = "A policy that initially has limited permissions"

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }

  // Initially this policy has minimal permissions
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

// Create a dangerous version (v2) of the policy using the admin provider
resource "null_resource" "create_dangerous_policy_version" {
  depends_on = [aws_iam_policy.vuln_iam_setdefaultpolicyversion_target_policy]

  provisioner "local-exec" {
    command = <<-EOT
      for i in 1 2 3 4 5; do
        aws iam create-policy-version \
          --policy-arn ${aws_iam_policy.vuln_iam_setdefaultpolicyversion_target_policy.arn} \
          --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
          --no-set-as-default && break
        echo "Attempt $i failed, retrying in $((i * 2))s..."
        sleep $((i * 2))
      done
    EOT
  }
}

// Create a slightly more permissive version (v3) of the policy using the admin provider
resource "null_resource" "create_moderate_policy_version" {
  depends_on = [null_resource.create_dangerous_policy_version]

  provisioner "local-exec" {
    command = <<-EOT
      for i in 1 2 3 4 5; do
        aws iam create-policy-version \
          --policy-arn ${aws_iam_policy.vuln_iam_setdefaultpolicyversion_target_policy.arn} \
          --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListAllMyBuckets","s3:GetBucketLocation","s3:ListBucket"],"Resource":"*"}]}' \
          --set-as-default && break
        echo "Attempt $i failed, retrying in $((i * 2))s..."
        sleep $((i * 2))
      done
    EOT
  }
}

// Create a permission policy to allow setting default policy versions
resource "aws_iam_policy" "vuln_iam_setdefaultpolicyversion_permission_policy" {
  name        = "vuln-iam-setdefaultpolicyversion-permission-${var.random_suffix}"
  description = "Policy that allows setting default policy versions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicyVersions",
          "iam:SetDefaultPolicyVersion"
        ]
        Resource = aws_iam_policy.vuln_iam_setdefaultpolicyversion_target_policy.arn
      }
    ]
  })
}

// Attach the permission policy to the user
resource "aws_iam_user_policy_attachment" "vuln_iam_setdefaultpolicyversion_permission_attach" {
  user       = aws_iam_user.vuln_iam_setdefaultpolicyversion_user.name
  policy_arn = aws_iam_policy.vuln_iam_setdefaultpolicyversion_permission_policy.arn
}

// Attach the target policy to the user (this gives them the permissions in the currently active version)
resource "aws_iam_user_policy_attachment" "vuln_iam_setdefaultpolicyversion_target_attach" {
  user       = aws_iam_user.vuln_iam_setdefaultpolicyversion_user.name
  policy_arn = aws_iam_policy.vuln_iam_setdefaultpolicyversion_target_policy.arn
  depends_on = [null_resource.create_moderate_policy_version]
}

// Output variables
output "vuln_iam_setdefaultpolicyversion_user_name" {
  value       = aws_iam_user.vuln_iam_setdefaultpolicyversion_user.name
  description = "Name of the vulnerable IAM user"
}

output "vuln_iam_setdefaultpolicyversion_target_policy_arn" {
  value       = aws_iam_policy.vuln_iam_setdefaultpolicyversion_target_policy.arn
  description = "ARN of the policy with multiple versions"
}