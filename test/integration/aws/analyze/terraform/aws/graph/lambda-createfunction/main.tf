# Lambda CreateFunction Privilege Escalation Scenario
# This creates a vulnerable scenario where a user can escalate privileges
# by creating a Lambda function with an existing privileged role

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

# Create a privileged Lambda execution role
resource "aws_iam_role" "vuln_lambda_createfunction_privileged_role" {
  name = "vuln-lambda-createfunction-privileged-role-${var.random_suffix}"

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
resource "aws_iam_role_policy_attachment" "vuln_lambda_createfunction_admin_policy" {
  role       = aws_iam_role.vuln_lambda_createfunction_privileged_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Create a vulnerable user with limited permissions but ability to create Lambda functions
resource "aws_iam_user" "vuln_lambda_createfunction_user" {
  name          = "vuln-lambda-createfunction-user-${var.random_suffix}"
  force_destroy = true
}

# Create access key for the vulnerable user
resource "aws_iam_access_key" "vuln_lambda_createfunction_user_key" {
  user = aws_iam_user.vuln_lambda_createfunction_user.name
}

# Create a simple Lambda function to test lambda:InvokeFunction permissions
resource "aws_lambda_function" "test_function" {
  filename      = "${path.module}/test_function.zip"
  function_name = "vuln-lambda-createfunction-test-function-${var.random_suffix}"
  role          = aws_iam_role.vuln_lambda_createfunction_privileged_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  depends_on = [data.archive_file.test_function_zip]
}

# Create a simple test function code
data "archive_file" "test_function_zip" {
  type        = "zip"
  output_path = "${path.module}/test_function.zip"
  source {
    content  = <<EOF
def handler(event, context):
    return {'statusCode': 200, 'body': 'Hello from Lambda!'}
EOF
    filename = "index.py"
  }
}

# Create a policy that allows the user to create Lambda functions and pass the privileged role
resource "aws_iam_policy" "vuln_lambda_createfunction_policy" {
  name = "vuln-lambda-createfunction-policy-${var.random_suffix}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
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
        Resource = [
          "*",
          aws_lambda_function.test_function.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = aws_iam_role.vuln_lambda_createfunction_privileged_role.arn
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:ListRoles"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach the policy to the vulnerable user
resource "aws_iam_user_policy_attachment" "vuln_lambda_createfunction_user_policy" {
  user       = aws_iam_user.vuln_lambda_createfunction_user.name
  policy_arn = aws_iam_policy.vuln_lambda_createfunction_policy.arn
}

# Output the resources for testing
output "vulnerable_user_name" {
  value = aws_iam_user.vuln_lambda_createfunction_user.name
}

output "vulnerable_user_access_key" {
  value     = aws_iam_access_key.vuln_lambda_createfunction_user_key.id
  sensitive = true
}

output "vulnerable_user_secret_key" {
  value     = aws_iam_access_key.vuln_lambda_createfunction_user_key.secret
  sensitive = true
}

output "privileged_role_arn" {
  value = aws_iam_role.vuln_lambda_createfunction_privileged_role.arn
}

output "privileged_role_name" {
  value = aws_iam_role.vuln_lambda_createfunction_privileged_role.name
}

output "test_function_name" {
  value = aws_lambda_function.test_function.function_name
} 