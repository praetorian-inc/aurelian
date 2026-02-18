package resourcepolicies

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	estypes "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	ostypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupportedResourceTypes(t *testing.T) {
	types := SupportedResourceTypes()
	assert.Len(t, types, 7)
	assert.Contains(t, types, "AWS::S3::Bucket")
	assert.Contains(t, types, "AWS::Lambda::Function")
	assert.Contains(t, types, "AWS::SNS::Topic")
	assert.Contains(t, types, "AWS::SQS::Queue")
	assert.Contains(t, types, "AWS::EFS::FileSystem")
	assert.Contains(t, types, "AWS::OpenSearchService::Domain")
	assert.Contains(t, types, "AWS::Elasticsearch::Domain")
}

// Mock S3 Client
type mockS3Client struct {
	policy *s3.GetBucketPolicyOutput
	err    error
}

func (m *mockS3Client) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	return m.policy, m.err
}

func TestFetchS3BucketPolicy_Success(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}`
	client := &mockS3Client{
		policy: &s3.GetBucketPolicyOutput{
			Policy: aws.String(policyJSON),
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "my-bucket",
		Properties: map[string]any{
			"BucketName": "my-bucket",
		},
	}

	policy, err := FetchS3BucketPolicy(context.Background(), client, resource)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "2012-10-17", policy.Version)
	assert.Len(t, *policy.Statement, 1)
}

func TestFetchS3BucketPolicy_NoPolicy(t *testing.T) {
	client := &mockS3Client{
		err: &s3types.NoSuchBucket{},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "my-bucket",
		Properties: map[string]any{
			"BucketName": "my-bucket",
		},
	}

	policy, err := FetchS3BucketPolicy(context.Background(), client, resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

func TestFetchS3BucketPolicy_MissingBucketName(t *testing.T) {
	client := &mockS3Client{}

	resource := &output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "my-bucket",
		Properties:   map[string]any{},
	}

	policy, err := FetchS3BucketPolicy(context.Background(), client, resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

// Mock Lambda Client
type mockLambdaClient struct {
	policy *lambda.GetPolicyOutput
	err    error
}

func (m *mockLambdaClient) GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	return m.policy, m.err
}

func TestFetchLambdaPolicy_Success(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"*"}]}`
	client := &mockLambdaClient{
		policy: &lambda.GetPolicyOutput{
			Policy: aws.String(policyJSON),
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "my-function",
		Properties: map[string]any{
			"FunctionName": "my-function",
		},
	}

	policy, err := FetchLambdaPolicy(context.Background(), client, resource)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "2012-10-17", policy.Version)
}

func TestFetchLambdaPolicy_NotFound(t *testing.T) {
	client := &mockLambdaClient{
		err: &lambdatypes.ResourceNotFoundException{},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "my-function",
		Properties: map[string]any{
			"FunctionName": "my-function",
		},
	}

	policy, err := FetchLambdaPolicy(context.Background(), client, resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

// Mock SNS Client
type mockSNSClient struct {
	attributes *sns.GetTopicAttributesOutput
	err        error
}

func (m *mockSNSClient) GetTopicAttributes(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	return m.attributes, m.err
}

func TestFetchSNSTopicPolicy_Success(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"SNS:Publish","Resource":"*"}]}`
	client := &mockSNSClient{
		attributes: &sns.GetTopicAttributesOutput{
			Attributes: map[string]string{
				"Policy": policyJSON,
			},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::SNS::Topic",
		ResourceID:   "arn:aws:sns:us-east-1:123456789012:my-topic",
		Properties: map[string]any{
			"TopicArn": "arn:aws:sns:us-east-1:123456789012:my-topic",
		},
	}

	policy, err := FetchSNSTopicPolicy(context.Background(), client, resource)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "2012-10-17", policy.Version)
}

func TestFetchSNSTopicPolicy_NoPolicy(t *testing.T) {
	client := &mockSNSClient{
		attributes: &sns.GetTopicAttributesOutput{
			Attributes: map[string]string{},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::SNS::Topic",
		ResourceID:   "arn:aws:sns:us-east-1:123456789012:my-topic",
		Properties: map[string]any{
			"TopicArn": "arn:aws:sns:us-east-1:123456789012:my-topic",
		},
	}

	policy, err := FetchSNSTopicPolicy(context.Background(), client, resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

// Mock SQS Client
type mockSQSClient struct {
	attributes *sqs.GetQueueAttributesOutput
	err        error
}

func (m *mockSQSClient) GetQueueAttributes(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	return m.attributes, m.err
}

func TestFetchSQSQueuePolicy_Success(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"SQS:SendMessage","Resource":"*"}]}`
	client := &mockSQSClient{
		attributes: &sqs.GetQueueAttributesOutput{
			Attributes: map[string]string{
				"Policy": policyJSON,
			},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::SQS::Queue",
		ResourceID:   "my-queue",
		Properties: map[string]any{
			"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue",
		},
	}

	policy, err := FetchSQSQueuePolicy(context.Background(), client, resource)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "2012-10-17", policy.Version)
}

// Mock EFS Client
type mockEFSClient struct {
	policy *efs.DescribeFileSystemPolicyOutput
	err    error
}

func (m *mockEFSClient) DescribeFileSystemPolicy(ctx context.Context, params *efs.DescribeFileSystemPolicyInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemPolicyOutput, error) {
	return m.policy, m.err
}

func TestFetchEFSPolicy_Success(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"elasticfilesystem:ClientMount","Resource":"*"}]}`
	client := &mockEFSClient{
		policy: &efs.DescribeFileSystemPolicyOutput{
			Policy: aws.String(policyJSON),
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::EFS::FileSystem",
		ResourceID:   "fs-12345678",
		Properties: map[string]any{
			"FileSystemId": "fs-12345678",
		},
	}

	policy, err := FetchEFSPolicy(context.Background(), client, resource)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "2012-10-17", policy.Version)
}

func TestFetchEFSPolicy_PolicyNotFound(t *testing.T) {
	client := &mockEFSClient{
		err: &efstypes.PolicyNotFound{},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::EFS::FileSystem",
		ResourceID:   "fs-12345678",
		Properties: map[string]any{
			"FileSystemId": "fs-12345678",
		},
	}

	policy, err := FetchEFSPolicy(context.Background(), client, resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

// Mock OpenSearch Client
type mockOpenSearchClient struct {
	config *opensearch.DescribeDomainConfigOutput
	err    error
}

func (m *mockOpenSearchClient) DescribeDomainConfig(ctx context.Context, params *opensearch.DescribeDomainConfigInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainConfigOutput, error) {
	return m.config, m.err
}

func TestFetchOpenSearchPolicy_Success(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"es:*","Resource":"*"}]}`
	client := &mockOpenSearchClient{
		config: &opensearch.DescribeDomainConfigOutput{
			DomainConfig: &ostypes.DomainConfig{
				AccessPolicies: &ostypes.AccessPoliciesStatus{
					Options: aws.String(policyJSON),
				},
			},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::OpenSearchService::Domain",
		ResourceID:   "my-domain",
		Properties: map[string]any{
			"DomainName": "my-domain",
		},
	}

	policy, err := FetchOpenSearchPolicy(context.Background(), client, resource)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "2012-10-17", policy.Version)
}

// Mock Elasticsearch Client
type mockElasticsearchClient struct {
	config *elasticsearchservice.DescribeElasticsearchDomainConfigOutput
	err    error
}

func (m *mockElasticsearchClient) DescribeElasticsearchDomainConfig(ctx context.Context, params *elasticsearchservice.DescribeElasticsearchDomainConfigInput, optFns ...func(*elasticsearchservice.Options)) (*elasticsearchservice.DescribeElasticsearchDomainConfigOutput, error) {
	return m.config, m.err
}

func TestFetchElasticsearchPolicy_Success(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"es:*","Resource":"*"}]}`
	client := &mockElasticsearchClient{
		config: &elasticsearchservice.DescribeElasticsearchDomainConfigOutput{
			DomainConfig: &estypes.ElasticsearchDomainConfig{
				AccessPolicies: &estypes.AccessPoliciesStatus{
					Options: aws.String(policyJSON),
				},
			},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Elasticsearch::Domain",
		ResourceID:   "my-domain",
		Properties: map[string]any{
			"DomainName": "my-domain",
		},
	}

	policy, err := FetchElasticsearchPolicy(context.Background(), client, resource)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "2012-10-17", policy.Version)
}

func TestCollectPolicies_Success(t *testing.T) {
	// We'll test this after adding the dependencies
	// For now, ensure the function signature is correct
	resources := []output.AWSResource{
		{
			ResourceType: "AWS::EC2::Instance", // Unsupported type
			ResourceID:   "i-12345",
			Properties:   map[string]any{},
		},
	}

	results, err := CollectPolicies(context.Background(), aws.Config{}, resources)
	assert.NoError(t, err)
	assert.Empty(t, results) // No supported types
}

func TestFetchS3BucketPolicy_NoSuchBucketPolicy(t *testing.T) {
	client := &mockS3Client{
		err: &smithy.GenericAPIError{
			Code:    "NoSuchBucketPolicy",
			Message: "The bucket policy does not exist",
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "my-bucket",
		Properties: map[string]any{
			"BucketName": "my-bucket",
		},
	}

	policy, err := FetchS3BucketPolicy(context.Background(), client, resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

func TestFetchSNSTopicPolicy_NotFound(t *testing.T) {
	client := &mockSNSClient{
		err: &snstypes.NotFoundException{},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::SNS::Topic",
		ResourceID:   "arn:aws:sns:us-east-1:123456789012:my-topic",
		Properties: map[string]any{
			"TopicArn": "arn:aws:sns:us-east-1:123456789012:my-topic",
		},
	}

	policy, err := FetchSNSTopicPolicy(context.Background(), client, resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

func TestFetchSQSQueuePolicy_NotFound(t *testing.T) {
	client := &mockSQSClient{
		err: &sqstypes.QueueDoesNotExist{},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::SQS::Queue",
		ResourceID:   "my-queue",
		Properties: map[string]any{
			"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue",
		},
	}

	policy, err := FetchSQSQueuePolicy(context.Background(), client, resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

func TestFetchOpenSearchPolicy_NotFound(t *testing.T) {
	client := &mockOpenSearchClient{
		err: &ostypes.ResourceNotFoundException{},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::OpenSearchService::Domain",
		ResourceID:   "my-domain",
		Properties: map[string]any{
			"DomainName": "my-domain",
		},
	}

	policy, err := FetchOpenSearchPolicy(context.Background(), client, resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

func TestFetchElasticsearchPolicy_NotFound(t *testing.T) {
	client := &mockElasticsearchClient{
		err: &estypes.ResourceNotFoundException{},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::Elasticsearch::Domain",
		ResourceID:   "my-domain",
		Properties: map[string]any{
			"DomainName": "my-domain",
		},
	}

	policy, err := FetchElasticsearchPolicy(context.Background(), client, resource)
	assert.NoError(t, err)
	assert.Nil(t, policy)
}
