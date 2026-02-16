# Lambda Event Source Mapping Privilege Escalation Scenario
# This creates a vulnerable scenario where a user can escalate privileges
# by creating a Lambda function with privilege escalation code, passing
# a privileged role to it, creating an event source mapping to a DynamoDB stream,
# then triggering execution by updating the DynamoDB table.

variable "random_suffix" {
  description = "Random suffix for resource names"
  type        = string
}

# Create a privileged Lambda execution role
resource "aws_iam_role" "vuln_lambda_eventsourcemapping_privileged_role" {
  name = "vuln-lambda-eventsourcemapping-privileged-role-${var.random_suffix}"

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
resource "aws_iam_role_policy_attachment" "vuln_lambda_eventsourcemapping_admin_policy" {
  role       = aws_iam_role.vuln_lambda_eventsourcemapping_privileged_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Create a DynamoDB table with streams enabled
resource "aws_dynamodb_table" "vuln_lambda_eventsourcemapping_table" {
  name         = "vuln-lambda-eventsourcemapping-table-${var.random_suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
}

# Create a vulnerable user with limited permissions but ability to manipulate Lambda and DynamoDB
resource "aws_iam_user" "vuln_lambda_eventsourcemapping_user" {
  name          = "vuln-lambda-eventsourcemapping-user-${var.random_suffix}"
  force_destroy = true
}

# Create a policy that allows the user to create Lambda functions, create event source mappings, and pass the privileged role
resource "aws_iam_policy" "vuln_lambda_eventsourcemapping_policy" {
  name = "vuln-lambda-eventsourcemapping-policy-${var.random_suffix}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:GetFunction",
          "lambda:ListFunctions",
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:CreateEventSourceMapping",
          "lambda:GetEventSourceMapping",
          "lambda:ListEventSourceMappings",
          "lambda:UpdateEventSourceMapping"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = aws_iam_role.vuln_lambda_eventsourcemapping_privileged_role.arn
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
          "dynamodb:DescribeTable",
          "dynamodb:DescribeStream",
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:ListStreams",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:GetItem"
        ]
        Resource = [
          aws_dynamodb_table.vuln_lambda_eventsourcemapping_table.arn,
          "${aws_dynamodb_table.vuln_lambda_eventsourcemapping_table.arn}/stream/*"
        ]
      }
    ]
  })
}

# Attach the policy to the vulnerable user
resource "aws_iam_user_policy_attachment" "vuln_lambda_eventsourcemapping_user_policy" {
  user       = aws_iam_user.vuln_lambda_eventsourcemapping_user.name
  policy_arn = aws_iam_policy.vuln_lambda_eventsourcemapping_policy.arn
}

# Create a target Lambda function (to demonstrate potential for creating new ones)
resource "aws_lambda_function" "vuln_lambda_eventsourcemapping_target_function" {
  filename      = "${path.module}/target_function.zip"
  function_name = "vuln-lambda-eventsourcemapping-target-function-${var.random_suffix}"
  role          = aws_iam_role.vuln_lambda_eventsourcemapping_privileged_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 30

  depends_on = [data.archive_file.target_function_zip]
}

# Create a target function with privilege escalation code
data "archive_file" "target_function_zip" {
  type        = "zip"
  output_path = "${path.module}/target_function.zip"
  source {
    content  = <<EOF
import boto3
import json

def handler(event, context):
    # This Lambda function demonstrates privilege escalation
    # It has AdministratorAccess through the role and can perform any AWS operation
    
    # Example privileged operation - list all IAM users (requires admin permissions)
    try:
        iam = boto3.client('iam')
        users = iam.list_users()
        
        print(f"Privilege escalation successful! Found {len(users['Users'])} IAM users:")
        for user in users['Users']:
            print(f"  - {user['UserName']}")
            
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Privilege escalation via Lambda Event Source Mapping successful!',
                'user_count': len(users['Users']),
                'triggered_by': 'DynamoDB Stream Event'
            })
        }
    except Exception as e:
        print(f"Error during privilege escalation: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
EOF
    filename = "index.py"
  }
}

# Create an event source mapping to connect DynamoDB stream to Lambda function
resource "aws_lambda_event_source_mapping" "vuln_lambda_eventsourcemapping_esm" {
  event_source_arn  = aws_dynamodb_table.vuln_lambda_eventsourcemapping_table.stream_arn
  function_name     = aws_lambda_function.vuln_lambda_eventsourcemapping_target_function.arn
  starting_position = "LATEST"
}

# Output the resources for testing
output "vulnerable_user_name" {
  value = aws_iam_user.vuln_lambda_eventsourcemapping_user.name
}

output "privileged_role_arn" {
  value = aws_iam_role.vuln_lambda_eventsourcemapping_privileged_role.arn
}

output "privileged_role_name" {
  value = aws_iam_role.vuln_lambda_eventsourcemapping_privileged_role.name
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.vuln_lambda_eventsourcemapping_table.name
}

output "dynamodb_stream_arn" {
  value = aws_dynamodb_table.vuln_lambda_eventsourcemapping_table.stream_arn
}

output "target_function_name" {
  value = aws_lambda_function.vuln_lambda_eventsourcemapping_target_function.function_name
}

output "event_source_mapping_uuid" {
  value = aws_lambda_event_source_mapping.vuln_lambda_eventsourcemapping_esm.uuid
} 