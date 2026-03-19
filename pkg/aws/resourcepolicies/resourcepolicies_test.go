package resourcepolicies_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcepolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock S3 Client
type mockS3Client struct {
	policy *s3.GetBucketPolicyOutput
	err    error
}

func (m *mockS3Client) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	return m.policy, m.err
}

// Mock Lambda Client
type mockLambdaClient struct {
	policy *lambda.GetPolicyOutput
	err    error
}

func (m *mockLambdaClient) GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	return m.policy, m.err
}

// Mock SNS Client
type mockSNSClient struct {
	attributes *sns.GetTopicAttributesOutput
	err        error
}

func (m *mockSNSClient) GetTopicAttributes(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	return m.attributes, m.err
}

// Mock SQS Client
type mockSQSClient struct {
	attributes *sqs.GetQueueAttributesOutput
	err        error
}

func (m *mockSQSClient) GetQueueAttributes(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	return m.attributes, m.err
}

// TestResourcePoliciesCollectPoliciesFlow tests the full CollectPolicies flow with multiple resource types
func TestResourcePoliciesCollectPoliciesFlow(t *testing.T) {
	// Valid policy JSON that NewPolicyFromJSON can parse
	validPolicyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::test-bucket/*"}]}`

	// Step 1: Create mock resources for different types
	s3Resource := output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "test-bucket",
		ARN:          "arn:aws:s3:::test-bucket",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   make(map[string]any),
	}

	lambdaResource := output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "test-function",
		ARN:          "arn:aws:lambda:us-east-1:123456789012:function:test-function",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties: map[string]any{
			"FunctionName": "test-function",
		},
	}

	snsResource := output.AWSResource{
		ResourceType: "AWS::SNS::Topic",
		ResourceID:   "test-topic",
		ARN:          "arn:aws:sns:us-east-1:123456789012:test-topic",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties: map[string]any{
			"TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
		},
	}

	sqsResource := output.AWSResource{
		ResourceType: "AWS::SQS::Queue",
		ResourceID:   "test-queue",
		ARN:          "arn:aws:sqs:us-east-1:123456789012:test-queue",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties: map[string]any{
			"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue",
		},
	}

	// Step 2: Call individual FetchXxxPolicy functions with mock clients
	ctx := context.Background()

	// Test S3
	s3Client := &mockS3Client{
		policy: &s3.GetBucketPolicyOutput{
			Policy: aws.String(validPolicyJSON),
		},
	}
	s3Policy, err := resourcepolicies.FetchS3BucketPolicy(ctx, s3Client, &s3Resource)
	require.NoError(t, err)
	require.NotNil(t, s3Policy)
	assert.Equal(t, "2012-10-17", s3Policy.Version)
	assert.Len(t, *s3Policy.Statement, 1)
	assert.Equal(t, "Allow", (*s3Policy.Statement)[0].Effect)
	assert.NotNil(t, (*s3Policy.Statement)[0].Action)
	assert.NotNil(t, (*s3Policy.Statement)[0].Principal)

	// Test Lambda
	lambdaClient := &mockLambdaClient{
		policy: &lambda.GetPolicyOutput{
			Policy: aws.String(validPolicyJSON),
		},
	}
	lambdaPolicy, err := resourcepolicies.FetchLambdaPolicy(ctx, lambdaClient, &lambdaResource)
	require.NoError(t, err)
	require.NotNil(t, lambdaPolicy)
	assert.Equal(t, "2012-10-17", lambdaPolicy.Version)
	assert.Len(t, *lambdaPolicy.Statement, 1)

	// Test SNS
	snsClient := &mockSNSClient{
		attributes: &sns.GetTopicAttributesOutput{
			Attributes: map[string]string{
				"Policy": validPolicyJSON,
			},
		},
	}
	snsPolicy, err := resourcepolicies.FetchSNSTopicPolicy(ctx, snsClient, &snsResource)
	require.NoError(t, err)
	require.NotNil(t, snsPolicy)
	assert.Equal(t, "2012-10-17", snsPolicy.Version)
	assert.Len(t, *snsPolicy.Statement, 1)

	// Test SQS
	sqsClient := &mockSQSClient{
		attributes: &sqs.GetQueueAttributesOutput{
			Attributes: map[string]string{
				"Policy": validPolicyJSON,
			},
		},
	}
	sqsPolicy, err := resourcepolicies.FetchSQSQueuePolicy(ctx, sqsClient, &sqsResource)
	require.NoError(t, err)
	require.NotNil(t, sqsPolicy)
	assert.Equal(t, "2012-10-17", sqsPolicy.Version)
	assert.Len(t, *sqsPolicy.Statement, 1)

	// Step 3: Verify we can marshal policy to JSON and add to Properties["ResourcePolicy"]
	policyJSON, err := json.Marshal(s3Policy)
	require.NoError(t, err)
	s3Resource.Properties["ResourcePolicy"] = string(policyJSON)

	// Step 4: Verify we can unmarshal it back
	var reconstructedPolicy types.Policy
	err = json.Unmarshal([]byte(s3Resource.Properties["ResourcePolicy"].(string)), &reconstructedPolicy)
	require.NoError(t, err)
	assert.Equal(t, "2012-10-17", reconstructedPolicy.Version)
	assert.Len(t, *reconstructedPolicy.Statement, 1)
	assert.Equal(t, "Allow", (*reconstructedPolicy.Statement)[0].Effect)
}

// TestResourcePoliciesNoPolicy tests that resources without policies return nil (not error)
func TestResourcePoliciesNoPolicy(t *testing.T) {
	ctx := context.Background()

	// Test S3 bucket with NoSuchBucketPolicy error
	s3Resource := output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "no-policy-bucket",
	}
	s3Client := &mockS3Client{
		policy: &s3.GetBucketPolicyOutput{
			Policy: nil, // No policy
		},
	}
	policy, err := resourcepolicies.FetchS3BucketPolicy(ctx, s3Client, &s3Resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)

	// Test Lambda with ResourceNotFoundException (returns nil, not error)
	lambdaResource := output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "no-policy-function",
		Properties: map[string]any{
			"FunctionName": "no-policy-function",
		},
	}
	lambdaClient := &mockLambdaClient{
		policy: &lambda.GetPolicyOutput{
			Policy: nil, // No policy
		},
	}
	policy, err = resourcepolicies.FetchLambdaPolicy(ctx, lambdaClient, &lambdaResource)
	assert.NoError(t, err)
	assert.Nil(t, policy)

	// Test SNS topic with empty Policy attribute
	snsResource := output.AWSResource{
		ResourceType: "AWS::SNS::Topic",
		ResourceID:   "no-policy-topic",
		Properties: map[string]any{
			"TopicArn": "arn:aws:sns:us-east-1:123456789012:no-policy-topic",
		},
	}
	snsClient := &mockSNSClient{
		attributes: &sns.GetTopicAttributesOutput{
			Attributes: map[string]string{}, // No Policy attribute
		},
	}
	policy, err = resourcepolicies.FetchSNSTopicPolicy(ctx, snsClient, &snsResource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

// TestResourcePoliciesSupportedTypes verifies SupportedResourceTypes returns all 7 expected types
func TestResourcePoliciesSupportedTypes(t *testing.T) {
	supportedTypes := resourcepolicies.SupportedResourceTypes()
	assert.Len(t, supportedTypes, 7)

	// Verify all expected types are present
	expectedTypes := []string{
		"AWS::S3::Bucket",
		"AWS::Lambda::Function",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::EFS::FileSystem",
		"AWS::OpenSearchService::Domain",
		"AWS::Elasticsearch::Domain",
	}

	for _, expectedType := range expectedTypes {
		assert.Contains(t, supportedTypes, expectedType, "Expected resource type %s not found", expectedType)
	}
}
