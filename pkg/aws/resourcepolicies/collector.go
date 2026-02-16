package resourcepolicies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// PolicyFetcher is a function that fetches a resource policy for a given CloudResource
type PolicyFetcher func(ctx context.Context, awsCfg aws.Config, resource *output.CloudResource) (*types.Policy, error)

// Fetchers maps resource types to their policy fetcher functions
var Fetchers = map[string]PolicyFetcher{
	"AWS::S3::Bucket":                    fetchS3BucketPolicy,
	"AWS::Lambda::Function":              fetchLambdaPolicy,
	"AWS::SNS::Topic":                    fetchSNSTopicPolicy,
	"AWS::SQS::Queue":                    fetchSQSQueuePolicy,
	"AWS::EFS::FileSystem":               fetchEFSPolicy,
	"AWS::OpenSearchService::Domain":     fetchOpenSearchPolicy,
	"AWS::Elasticsearch::Domain":         fetchElasticsearchPolicy,
}

// SupportedResourceTypes returns the list of resource types that have policy fetchers
func SupportedResourceTypes() []string {
	types := make([]string, 0, len(Fetchers))
	for resourceType := range Fetchers {
		types = append(types, resourceType)
	}
	return types
}

// CollectPolicies fetches policies for resources that support them and adds them to resource.Properties["ResourcePolicy"]
// Returns only resources that have policies
func CollectPolicies(ctx context.Context, awsCfg aws.Config, resources []output.CloudResource) ([]output.CloudResource, error) {
	var results []output.CloudResource

	for _, resource := range resources {
		fetcher, ok := Fetchers[resource.ResourceType]
		if !ok {
			// Resource type doesn't support policies, skip
			continue
		}

		policy, err := fetcher(ctx, awsCfg, &resource)
		if err != nil {
			return nil, fmt.Errorf("fetch policy for %s (%s): %w", resource.ResourceID, resource.ResourceType, err)
		}

		if policy != nil {
			// Marshal policy to JSON and add to Properties
			policyJSON, err := json.Marshal(policy)
			if err != nil {
				return nil, fmt.Errorf("marshal policy for %s: %w", resource.ResourceID, err)
			}
			resource.Properties["ResourcePolicy"] = string(policyJSON)
			results = append(results, resource)
		}
	}

	return results, nil
}

// S3Client interface for S3 operations
type S3Client interface {
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
}

func fetchS3BucketPolicy(ctx context.Context, awsCfg aws.Config, resource *output.CloudResource) (*types.Policy, error) {
	client := s3.NewFromConfig(awsCfg)
	return FetchS3BucketPolicy(ctx, client, resource)
}

// FetchS3BucketPolicy retrieves the bucket policy for an S3 bucket
func FetchS3BucketPolicy(ctx context.Context, client S3Client, resource *output.CloudResource) (*types.Policy, error) {
	bucketName, ok := resource.Properties["BucketName"].(string)
	if !ok || bucketName == "" {
		return nil, nil
	}

	out, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: &bucketName,
	})
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

func fetchLambdaPolicy(ctx context.Context, awsCfg aws.Config, resource *output.CloudResource) (*types.Policy, error) {
	client := lambda.NewFromConfig(awsCfg)
	return FetchLambdaPolicy(ctx, client, resource)
}

// FetchLambdaPolicy retrieves the resource policy for a Lambda function
func FetchLambdaPolicy(ctx context.Context, client LambdaClient, resource *output.CloudResource) (*types.Policy, error) {
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

func fetchSNSTopicPolicy(ctx context.Context, awsCfg aws.Config, resource *output.CloudResource) (*types.Policy, error) {
	client := sns.NewFromConfig(awsCfg)
	return FetchSNSTopicPolicy(ctx, client, resource)
}

// FetchSNSTopicPolicy retrieves the access policy for an SNS topic
func FetchSNSTopicPolicy(ctx context.Context, client SNSClient, resource *output.CloudResource) (*types.Policy, error) {
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

func fetchSQSQueuePolicy(ctx context.Context, awsCfg aws.Config, resource *output.CloudResource) (*types.Policy, error) {
	client := sqs.NewFromConfig(awsCfg)
	return FetchSQSQueuePolicy(ctx, client, resource)
}

// FetchSQSQueuePolicy retrieves the access policy for an SQS queue
func FetchSQSQueuePolicy(ctx context.Context, client SQSClient, resource *output.CloudResource) (*types.Policy, error) {
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

func fetchEFSPolicy(ctx context.Context, awsCfg aws.Config, resource *output.CloudResource) (*types.Policy, error) {
	client := efs.NewFromConfig(awsCfg)
	return FetchEFSPolicy(ctx, client, resource)
}

// FetchEFSPolicy retrieves the resource policy for an EFS file system
func FetchEFSPolicy(ctx context.Context, client EFSClient, resource *output.CloudResource) (*types.Policy, error) {
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

func fetchOpenSearchPolicy(ctx context.Context, awsCfg aws.Config, resource *output.CloudResource) (*types.Policy, error) {
	client := opensearch.NewFromConfig(awsCfg)
	return FetchOpenSearchPolicy(ctx, client, resource)
}

// FetchOpenSearchPolicy retrieves the access policy for an OpenSearch domain
func FetchOpenSearchPolicy(ctx context.Context, client OpenSearchClient, resource *output.CloudResource) (*types.Policy, error) {
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

func fetchElasticsearchPolicy(ctx context.Context, awsCfg aws.Config, resource *output.CloudResource) (*types.Policy, error) {
	client := elasticsearchservice.NewFromConfig(awsCfg)
	return FetchElasticsearchPolicy(ctx, client, resource)
}

// FetchElasticsearchPolicy retrieves the access policy for an Elasticsearch domain
func FetchElasticsearchPolicy(ctx context.Context, client ElasticsearchClient, resource *output.CloudResource) (*types.Policy, error) {
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
