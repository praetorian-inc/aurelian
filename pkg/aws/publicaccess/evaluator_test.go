package publicaccess

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateResourcePolicy_NilPolicy(t *testing.T) {
	result, err := EvaluateResourcePolicy(nil, "arn:aws:s3:::my-bucket", "123456789012", "AWS::S3::Bucket", nil)
	require.NoError(t, err)
	assert.False(t, result.IsPublic)
}

func TestEvaluateResourcePolicy_PublicS3Policy(t *testing.T) {
	policy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Sid:    "PublicRead",
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"*"}),
				},
				Action:   types.NewDynaString([]string{"s3:GetObject"}),
				Resource: types.NewDynaString([]string{"arn:aws:s3:::my-bucket/*"}),
			},
		},
	}

	result, err := EvaluateResourcePolicy(policy, "arn:aws:s3:::my-bucket/*", "123456789012", "AWS::S3::Bucket", nil)
	require.NoError(t, err)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.AllowedActions, "s3:GetObject")
}

func TestEvaluateResourcePolicy_PrivateS3Policy(t *testing.T) {
	policy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Sid:    "AccountOnly",
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"arn:aws:iam::123456789012:root"}),
				},
				Action:   types.NewDynaString([]string{"s3:GetObject"}),
				Resource: types.NewDynaString([]string{"arn:aws:s3:::my-bucket/*"}),
			},
		},
	}

	result, err := EvaluateResourcePolicy(policy, "arn:aws:s3:::my-bucket/*", "123456789012", "AWS::S3::Bucket", nil)
	require.NoError(t, err)
	assert.False(t, result.IsPublic)
}

func TestEvaluateResourcePolicy_PublicSNSPolicy(t *testing.T) {
	policy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Sid:    "PublicPublish",
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"*"}),
				},
				Action:   types.NewDynaString([]string{"sns:Publish"}),
				Resource: types.NewDynaString([]string{"arn:aws:sns:us-east-1:123456789012:my-topic"}),
			},
		},
	}

	result, err := EvaluateResourcePolicy(policy, "arn:aws:sns:us-east-1:123456789012:my-topic", "123456789012", "AWS::SNS::Topic", nil)
	require.NoError(t, err)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.AllowedActions, "sns:Publish")
}

func TestEvaluateResourcePolicy_PublicSQSPolicy(t *testing.T) {
	policy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Sid:    "PublicSend",
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"*"}),
				},
				Action:   types.NewDynaString([]string{"sqs:SendMessage"}),
				Resource: types.NewDynaString([]string{"arn:aws:sqs:us-east-1:123456789012:my-queue"}),
			},
		},
	}

	result, err := EvaluateResourcePolicy(policy, "arn:aws:sqs:us-east-1:123456789012:my-queue", "123456789012", "AWS::SQS::Queue", nil)
	require.NoError(t, err)
	assert.True(t, result.IsPublic)
	assert.Contains(t, result.AllowedActions, "sqs:SendMessage")
}

func TestEvaluateResourcePolicy_DenyOverridesAllow(t *testing.T) {
	policy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Sid:    "AllowAll",
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"*"}),
				},
				Action:   types.NewDynaString([]string{"s3:GetObject"}),
				Resource: types.NewDynaString([]string{"arn:aws:s3:::my-bucket/*"}),
			},
			{
				Sid:    "DenyAll",
				Effect: "Deny",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"*"}),
				},
				Action:   types.NewDynaString([]string{"s3:*"}),
				Resource: types.NewDynaString([]string{"arn:aws:s3:::my-bucket/*"}),
			},
		},
	}

	result, err := EvaluateResourcePolicy(policy, "arn:aws:s3:::my-bucket/*", "123456789012", "AWS::S3::Bucket", nil)
	require.NoError(t, err)
	assert.False(t, result.IsPublic)
}

func TestEvaluateResourcePolicy_UnsupportedResourceType(t *testing.T) {
	policy := &types.Policy{
		Version:   "2012-10-17",
		Statement: &types.PolicyStatementList{},
	}

	_, err := EvaluateResourcePolicy(policy, "arn:aws:foo:us-east-1:123456789012:bar", "123456789012", "AWS::Foo::Bar", nil)
	assert.Error(t, err)
}

func TestAppendUnique(t *testing.T) {
	slice := []string{"a", "b"}
	slice = appendUnique(slice, "b")
	assert.Equal(t, []string{"a", "b"}, slice)
	slice = appendUnique(slice, "c")
	assert.Equal(t, []string{"a", "b", "c"}, slice)
}

func TestEvaluateResourcePolicy_InconclusiveCondition(t *testing.T) {
	// Policy with a condition using aws:SourceVpc (a critical key) which the evaluator
	// cannot resolve without context, triggering inconclusive evaluation
	policy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Sid:    "ConditionalAllow",
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"*"}),
				},
				Action:   types.NewDynaString([]string{"s3:GetObject"}),
				Resource: types.NewDynaString([]string{"arn:aws:s3:::my-bucket/*"}),
				Condition: &types.Condition{
					"StringEquals": {
						"aws:SourceVpc": types.DynaString{"vpc-12345"},
					},
				},
			},
		},
	}

	result, err := EvaluateResourcePolicy(policy, "arn:aws:s3:::my-bucket/*", "123456789012", "AWS::S3::Bucket", nil)
	require.NoError(t, err)
	// The policy has a condition with a critical key that can't be fully evaluated
	assert.True(t, result.NeedsManualTriage, "should flag inconclusive conditions for manual triage")
	assert.NotEmpty(t, result.EvaluationReasons, "should explain why manual triage is needed")
}
