package iam

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionClassifier_Classify(t *testing.T) {
	classifier := &ActionClassifier{}

	t.Run("Classify valid action", func(t *testing.T) {
		action := "appsync:ListApiKeys"

		categories, found := classifier.Classify(action)
		require.True(t, found)

		expected := []string{"CredentialExposure"}
		assert.Equal(t, expected, categories)
	})

	t.Run("Classify unknown action", func(t *testing.T) {
		action := "fake:NonExistentAction"

		_, found := classifier.Classify(action)
		assert.False(t, found)
	})
}

// readOnlyAccessPolicyStr is a slimmed-down version of the AWS ReadOnlyAccess managed policy
// (arn:aws:iam::aws:policy/ReadOnlyAccess). The real policy has 2 statement groups covering
// hundreds of services. This subset preserves the structure and exercises the classifier
// with representative actions including wildcards, specific actions, and classifiable entries.
// Source: https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html
var readOnlyAccessPolicyStr = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyActionsGroup1",
      "Effect": "Allow",
      "Action": [
        "access-analyzer:GetAnalyzer",
        "access-analyzer:GetFinding",
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",
        "access-analyzer:ValidatePolicy",
        "acm:Describe*",
        "acm:Get*",
        "acm:List*",
        "appsync:Get*",
        "appsync:List*",
        "cloudformation:Describe*",
        "cloudformation:Get*",
        "cloudformation:List*",
        "cloudfront:Describe*",
        "cloudfront:Get*",
        "cloudfront:List*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "cloudtrail:LookupEvents",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "codebuild:BatchGet*",
        "codebuild:List*",
        "codecommit:BatchGet*",
        "codecommit:Describe*",
        "codecommit:Get*",
        "codecommit:GitPull",
        "codecommit:List*",
        "cognito-identity:Describe*",
        "cognito-identity:GetCredentialsForIdentity",
        "cognito-identity:GetIdentityPoolRoles",
        "cognito-identity:GetOpenIdToken",
        "cognito-identity:List*",
        "config:Describe*",
        "config:Get*",
        "config:List*",
        "dynamodb:BatchGet*",
        "dynamodb:Describe*",
        "dynamodb:Get*",
        "dynamodb:List*",
        "dynamodb:Query",
        "dynamodb:Scan",
        "ec2:Describe*",
        "ec2:Get*",
        "ecr:BatchCheck*",
        "ecr:BatchGet*",
        "ecr:Describe*",
        "ecr:Get*",
        "ecr:List*",
        "ecs:Describe*",
        "ecs:List*",
        "eks:Describe*",
        "eks:List*",
        "elasticloadbalancing:Describe*",
        "es:Describe*",
        "es:ESHttpGet",
        "es:Get*",
        "es:List*",
        "events:Describe*",
        "events:List*",
        "firehose:Describe*",
        "firehose:List*",
        "glue:BatchGetCrawlers",
        "glue:BatchGetJobs",
        "glue:GetCrawler",
        "glue:GetDatabase",
        "glue:GetDatabases",
        "glue:GetJob",
        "glue:GetTable",
        "glue:GetTables",
        "glue:ListCrawlers",
        "glue:ListJobs",
        "guardduty:Describe*",
        "guardduty:Get*",
        "guardduty:List*",
        "iam:Generate*",
        "iam:Get*",
        "iam:List*",
        "iam:Simulate*",
        "inspector2:BatchGetAccountStatus",
        "inspector2:DescribeOrganizationConfiguration",
        "inspector2:GetConfiguration",
        "inspector2:ListFindings",
        "inspector2:ListCoverage"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadOnlyActionsGroup2",
      "Effect": "Allow",
      "Action": [
        "kafka:Describe*",
        "kafka:Get*",
        "kafka:List*",
        "kinesis:Describe*",
        "kinesis:Get*",
        "kinesis:List*",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "lambda:Get*",
        "lambda:List*",
        "logs:Describe*",
        "logs:FilterLogEvents",
        "logs:Get*",
        "logs:List*",
        "logs:StartQuery",
        "logs:StopQuery",
        "rds:Describe*",
        "rds:List*",
        "route53:Get*",
        "route53:List*",
        "route53:Test*",
        "s3:DescribeJob",
        "s3:Get*",
        "s3:List*",
        "secretsmanager:Describe*",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:Get*",
        "sqs:List*",
        "sqs:Receive*",
        "ssm:Describe*",
        "ssm:Get*",
        "ssm:List*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}`

func TestActionClassifier_FullPolicy(t *testing.T) {
	t.Setenv("GO_TEST_TIMEOUT", "60s")

	classifier := &ActionClassifier{}
	expander := &ActionExpander{}

	t.Run("Process full policy", func(t *testing.T) {
		var roa types.Policy
		if err := json.Unmarshal([]byte(readOnlyAccessPolicyStr), &roa); err != nil {
			t.Fatalf("Failed to unmarshal ReadOnlyAccess policy: %v", err)
		}

		results := make(map[string][]string)

		for _, statement := range *roa.Statement {
			if statement.Effect == "Allow" {
				if statement.Action != nil {
					for _, action := range *statement.Action {
						// Expand action
						expandedActions, err := expander.Expand(action)
						require.NoError(t, err)

						// Classify each expanded action
						for _, expandedAction := range expandedActions {
							categories, found := classifier.Classify(expandedAction)
							if found {
								results[expandedAction] = categories
								t.Logf("%s: %v\n", expandedAction, categories)
							}
						}
					}
				}
			}
		}

		assert.NotEmpty(t, results, "Expected to classify at least some actions from ReadOnlyAccess policy")
	})
}
