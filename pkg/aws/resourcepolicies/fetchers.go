package resourcepolicies

import (
	"context"
	"errors"
	"fmt"

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
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// SupportedResourceTypes returns the resource types that have policy fetchers.
// This is a convenience wrapper around ResourcePolicyCollector.SupportedResourceTypes().
func SupportedResourceTypes() []string {
	return New(plugin.AWSCommonRecon{}).SupportedResourceTypes()
}

// S3Client interface for S3 operations
type S3Client interface {
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
}

// FetchS3BucketPolicy retrieves the bucket policy for an S3 bucket
func FetchS3BucketPolicy(ctx context.Context, client S3Client, resource *output.AWSResource, optFns ...func(*s3.Options)) (*types.Policy, error) {
	bucketName := resource.ResourceID
	if bucketName == "" {
		return nil, nil
	}

	out, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: &bucketName,
	}, optFns...)
	if err != nil {
		var noSuchBucket *s3types.NoSuchBucket
		if errors.As(err, &noSuchBucket) {
			return nil, nil
		}
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchBucketPolicy" {
			return nil, nil
		}
		return nil, fmt.Errorf("get bucket policy: %w", err)
	}

	if out.Policy == nil {
		return nil, nil
	}

	return types.NewPolicyFromJSON([]byte(*out.Policy))
}

// LambdaClient interface for Lambda operations
type LambdaClient interface {
	GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// FetchLambdaPolicy retrieves the resource policy for a Lambda function
func FetchLambdaPolicy(ctx context.Context, client LambdaClient, resource *output.AWSResource) (*types.Policy, error) {
	functionName, ok := resource.Properties["FunctionName"].(string)
	if !ok || functionName == "" {
		return nil, nil
	}

	out, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{
		FunctionName: &functionName,
	})
	if err != nil {
		var notFound *lambdatypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get function policy: %w", err)
	}

	if out.Policy == nil {
		return nil, nil
	}

	return types.NewPolicyFromJSON([]byte(*out.Policy))
}

// SNSClient interface for SNS operations
type SNSClient interface {
	GetTopicAttributes(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
}

// FetchSNSTopicPolicy retrieves the access policy for an SNS topic
func FetchSNSTopicPolicy(ctx context.Context, client SNSClient, resource *output.AWSResource) (*types.Policy, error) {
	topicArn, ok := resource.Properties["TopicArn"].(string)
	if !ok || topicArn == "" {
		return nil, nil
	}

	out, err := client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
		TopicArn: &topicArn,
	})
	if err != nil {
		var notFound *snstypes.NotFoundException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get topic attributes: %w", err)
	}

	policyStr, ok := out.Attributes["Policy"]
	if !ok || policyStr == "" {
		return nil, nil
	}

	return types.NewPolicyFromJSON([]byte(policyStr))
}

// SQSClient interface for SQS operations
type SQSClient interface {
	GetQueueAttributes(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

// FetchSQSQueuePolicy retrieves the access policy for an SQS queue
func FetchSQSQueuePolicy(ctx context.Context, client SQSClient, resource *output.AWSResource) (*types.Policy, error) {
	queueURL, ok := resource.Properties["QueueUrl"].(string)
	if !ok || queueURL == "" {
		return nil, nil
	}

	out, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       &queueURL,
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNamePolicy},
	})
	if err != nil {
		var notFound *sqstypes.QueueDoesNotExist
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get queue attributes: %w", err)
	}

	policyStr, ok := out.Attributes["Policy"]
	if !ok || policyStr == "" {
		return nil, nil
	}

	return types.NewPolicyFromJSON([]byte(policyStr))
}

// EFSClient interface for EFS operations
type EFSClient interface {
	DescribeFileSystemPolicy(ctx context.Context, params *efs.DescribeFileSystemPolicyInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemPolicyOutput, error)
}

// FetchEFSPolicy retrieves the resource policy for an EFS file system
func FetchEFSPolicy(ctx context.Context, client EFSClient, resource *output.AWSResource) (*types.Policy, error) {
	fileSystemID, ok := resource.Properties["FileSystemId"].(string)
	if !ok || fileSystemID == "" {
		return nil, nil
	}

	out, err := client.DescribeFileSystemPolicy(ctx, &efs.DescribeFileSystemPolicyInput{
		FileSystemId: &fileSystemID,
	})
	if err != nil {
		var notFound *efstypes.PolicyNotFound
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("describe file system policy: %w", err)
	}

	if out.Policy == nil {
		return nil, nil
	}

	return types.NewPolicyFromJSON([]byte(*out.Policy))
}

// OpenSearchClient interface for OpenSearch operations
type OpenSearchClient interface {
	DescribeDomainConfig(ctx context.Context, params *opensearch.DescribeDomainConfigInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainConfigOutput, error)
}

// FetchOpenSearchPolicy retrieves the access policy for an OpenSearch domain
func FetchOpenSearchPolicy(ctx context.Context, client OpenSearchClient, resource *output.AWSResource) (*types.Policy, error) {
	domainName, ok := resource.Properties["DomainName"].(string)
	if !ok || domainName == "" {
		return nil, nil
	}

	out, err := client.DescribeDomainConfig(ctx, &opensearch.DescribeDomainConfigInput{
		DomainName: &domainName,
	})
	if err != nil {
		var notFound *ostypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("describe domain config: %w", err)
	}

	if out.DomainConfig == nil || out.DomainConfig.AccessPolicies == nil || out.DomainConfig.AccessPolicies.Options == nil {
		return nil, nil
	}

	return types.NewPolicyFromJSON([]byte(*out.DomainConfig.AccessPolicies.Options))
}

// ElasticsearchClient interface for Elasticsearch operations
type ElasticsearchClient interface {
	DescribeElasticsearchDomainConfig(ctx context.Context, params *elasticsearchservice.DescribeElasticsearchDomainConfigInput, optFns ...func(*elasticsearchservice.Options)) (*elasticsearchservice.DescribeElasticsearchDomainConfigOutput, error)
}

// FetchElasticsearchPolicy retrieves the access policy for an Elasticsearch domain
func FetchElasticsearchPolicy(ctx context.Context, client ElasticsearchClient, resource *output.AWSResource) (*types.Policy, error) {
	domainName, ok := resource.Properties["DomainName"].(string)
	if !ok || domainName == "" {
		return nil, nil
	}

	out, err := client.DescribeElasticsearchDomainConfig(ctx, &elasticsearchservice.DescribeElasticsearchDomainConfigInput{
		DomainName: &domainName,
	})
	if err != nil {
		var notFound *estypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("describe elasticsearch domain config: %w", err)
	}

	if out.DomainConfig == nil || out.DomainConfig.AccessPolicies == nil || out.DomainConfig.AccessPolicies.Options == nil {
		return nil, nil
	}

	return types.NewPolicyFromJSON([]byte(*out.DomainConfig.AccessPolicies.Options))
}
