variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

// Create a high-privilege execution role for ECS tasks
resource "aws_iam_role" "vuln_ecs_task_execution_role" {
  name = "vuln-ecs-registertaskdefinition-execution-role-${var.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
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

// Create a high-privilege task role for ECS tasks
resource "aws_iam_role" "vuln_ecs_task_role" {
  name = "vuln-ecs-registertaskdefinition-task-role-${var.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
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

// Create a high-privilege policy for the execution role
resource "aws_iam_policy" "vuln_ecs_execution_policy" {
  name        = "vuln-ecs-registertaskdefinition-execution-policy-${var.random_suffix}"
  description = "Policy with elevated permissions for ECS task execution"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
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

// Create a high-privilege policy for the task role
resource "aws_iam_policy" "vuln_ecs_task_policy" {
  name        = "vuln-ecs-registertaskdefinition-task-policy-${var.random_suffix}"
  description = "Policy with elevated permissions for ECS tasks"

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
          "lambda:*",
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

// Attach policies to the execution role
resource "aws_iam_role_policy_attachment" "vuln_ecs_execution_attach" {
  role       = aws_iam_role.vuln_ecs_task_execution_role.name
  policy_arn = aws_iam_policy.vuln_ecs_execution_policy.arn
}

// Attach policies to the task role
resource "aws_iam_role_policy_attachment" "vuln_ecs_task_attach" {
  role       = aws_iam_role.vuln_ecs_task_role.name
  policy_arn = aws_iam_policy.vuln_ecs_task_policy.arn
}

// Create an ECS cluster
resource "aws_ecs_cluster" "vuln_ecs_cluster" {
  name = "vuln-ecs-registertaskdefinition-cluster-${var.random_suffix}"

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Create an attacker user with ECS permissions
resource "aws_iam_user" "vuln_ecs_attacker" {
  name          = "vuln-ecs-registertaskdefinition-attacker-${var.random_suffix}"
  force_destroy = true
  path          = "/users/"

  lifecycle {
    ignore_changes = [
      tags,
      tags_all
    ]
  }
}

// Create a policy allowing the attacker to register task definitions and run tasks
resource "aws_iam_policy" "vuln_ecs_attacker_policy" {
  name        = "vuln-ecs-registertaskdefinition-attacker-policy-${var.random_suffix}"
  description = "Policy that allows registering task definitions and running ECS tasks"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:RegisterTaskDefinition",
          "ecs:RunTask",
          "ecs:DescribeTaskDefinition",
          "ecs:DescribeTasks",
          "ecs:ListTasks",
          "ecs:DescribeClusters",
          "ecs:ListClusters",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          aws_iam_role.vuln_ecs_task_execution_role.arn,
          aws_iam_role.vuln_ecs_task_role.arn
        ]
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
resource "aws_iam_user_policy_attachment" "vuln_ecs_attacker_attach" {
  user       = aws_iam_user.vuln_ecs_attacker.name
  policy_arn = aws_iam_policy.vuln_ecs_attacker_policy.arn
}

// Output variables
output "vuln_ecs_attacker_username" {
  value       = aws_iam_user.vuln_ecs_attacker.name
  description = "Username of the attacker with ECS permissions"
}

output "vuln_ecs_task_execution_role_arn" {
  value       = aws_iam_role.vuln_ecs_task_execution_role.arn
  description = "ARN of the ECS task execution role with elevated permissions"
}

output "vuln_ecs_task_role_arn" {
  value       = aws_iam_role.vuln_ecs_task_role.arn
  description = "ARN of the ECS task role with elevated permissions"
}

output "vuln_ecs_cluster_name" {
  value       = aws_ecs_cluster.vuln_ecs_cluster.name
  description = "Name of the ECS cluster"
} 