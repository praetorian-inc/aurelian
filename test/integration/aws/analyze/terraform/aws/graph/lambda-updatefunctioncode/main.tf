# Lambda UpdateFunctionCode Privilege Escalation Scenario
# This creates a vulnerable scenario where a user can escalate privileges
# by updating the code of an existing Lambda function with a privileged role

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

# Create a privileged Lambda execution role
resource "aws_iam_role" "vuln_lambda_updatefunctioncode_privileged_role" {
  name = "vuln-lambda-updatefunctioncode-privileged-role-${var.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Attach AdministratorAccess policy to the Lambda role (making it highly privileged)
resource "aws_iam_role_policy_attachment" "vuln_lambda_updatefunctioncode_admin_policy" {
  role       = aws_iam_role.vuln_lambda_updatefunctioncode_privileged_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Create a vulnerable user with limited permissions but ability to update Lambda function code
resource "aws_iam_user" "vuln_lambda_updatefunctioncode_user" {
  name          = "vuln-lambda-updatefunctioncode-user-${var.random_suffix}"
  force_destroy = true
}

# Create access key for the vulnerable user
resource "aws_iam_access_key" "vuln_lambda_updatefunctioncode_user_key" {
  user = aws_iam_user.vuln_lambda_updatefunctioncode_user.name
}

# Create an existing Lambda function with the privileged role that can be updated
resource "aws_lambda_function" "vuln_lambda_updatefunctioncode_target_function" {
  filename      = "${path.module}/target_function.zip"
  function_name = "vuln-lambda-updatefunctioncode-target-function-${var.random_suffix}"
  role          = aws_iam_role.vuln_lambda_updatefunctioncode_privileged_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  depends_on = [data.archive_file.target_function_zip]
}

# Create the initial function code (benign)
data "archive_file" "target_function_zip" {
  type        = "zip"
  output_path = "${path.module}/target_function.zip"
  source {
    content  = <<EOF
def handler(event, context):
    return {'statusCode': 200, 'body': 'Original benign function'}
EOF
    filename = "index.py"
  }
}

# Create a policy that allows the user to update Lambda function code
resource "aws_iam_policy" "vuln_lambda_updatefunctioncode_policy" {
  name = "vuln-lambda-updatefunctioncode-policy-${var.random_suffix}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:GetFunction",
          "lambda:ListFunctions"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = aws_lambda_function.vuln_lambda_updatefunctioncode_target_function.arn
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:ListRoles"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = aws_iam_role.vuln_lambda_updatefunctioncode_new_role.arn
      }
    ]
  })
}

# Attach the policy to the vulnerable user
resource "aws_iam_user_policy_attachment" "vuln_lambda_updatefunctioncode_user_policy" {
  user       = aws_iam_user.vuln_lambda_updatefunctioncode_user.name
  policy_arn = aws_iam_policy.vuln_lambda_updatefunctioncode_policy.arn
}

# Create a new execution role that can assume an admin role
resource "aws_iam_role" "vuln_lambda_updatefunctioncode_new_role" {
  name = "vuln-lambda-updatefunctioncode-new-role-${var.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Create an admin role that can be assumed by the new execution role
resource "aws_iam_role" "vuln_lambda_updatefunctioncode_admin_role" {
  name = "vuln-lambda-updatefunctioncode-admin-role-${var.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.vuln_lambda_updatefunctioncode_new_role.arn
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach AdministratorAccess policy to the admin role
resource "aws_iam_role_policy_attachment" "vuln_lambda_updatefunctioncode_admin_role_policy" {
  role       = aws_iam_role.vuln_lambda_updatefunctioncode_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Allow the new execution role to assume the admin role
resource "aws_iam_policy" "vuln_lambda_updatefunctioncode_new_role_assume_admin" {
  name = "vuln-lambda-updatefunctioncode-new-role-assume-admin-${var.random_suffix}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = aws_iam_role.vuln_lambda_updatefunctioncode_admin_role.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "vuln_lambda_updatefunctioncode_new_role_assume_admin_attach" {
  role       = aws_iam_role.vuln_lambda_updatefunctioncode_new_role.name
  policy_arn = aws_iam_policy.vuln_lambda_updatefunctioncode_new_role_assume_admin.arn
}

# Output the resources for testing
output "vulnerable_user_name" {
  value = aws_iam_user.vuln_lambda_updatefunctioncode_user.name
}

output "vulnerable_user_access_key" {
  value     = aws_iam_access_key.vuln_lambda_updatefunctioncode_user_key.id
  sensitive = true
}

output "vulnerable_user_secret_key" {
  value     = aws_iam_access_key.vuln_lambda_updatefunctioncode_user_key.secret
  sensitive = true
}

output "privileged_role_arn" {
  value = aws_iam_role.vuln_lambda_updatefunctioncode_privileged_role.arn
}

output "privileged_role_name" {
  value = aws_iam_role.vuln_lambda_updatefunctioncode_privileged_role.name
}

output "target_function_name" {
  value = aws_lambda_function.vuln_lambda_updatefunctioncode_target_function.function_name
}

output "target_function_arn" {
  value = aws_lambda_function.vuln_lambda_updatefunctioncode_target_function.arn
}

# Output the new roles for testing
output "new_execution_role_arn" {
  value = aws_iam_role.vuln_lambda_updatefunctioncode_new_role.arn
}

output "new_execution_role_name" {
  value = aws_iam_role.vuln_lambda_updatefunctioncode_new_role.name
}

output "admin_role_arn" {
  value = aws_iam_role.vuln_lambda_updatefunctioncode_admin_role.arn
}

output "admin_role_name" {
  value = aws_iam_role.vuln_lambda_updatefunctioncode_admin_role.name
} 