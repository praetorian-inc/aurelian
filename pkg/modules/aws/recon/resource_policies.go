package recon

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&ResourcePoliciesModule{})
}

// ResourcePoliciesModule fetches resource policies for AWS resources
type ResourcePoliciesModule struct{}

func (m *ResourcePoliciesModule) ID() string {
	return "resource-policies"
}

func (m *ResourcePoliciesModule) Name() string {
	return "AWS Get Resource Policies"
}

func (m *ResourcePoliciesModule) Description() string {
	return "Get resource policies for supported AWS resource types and output them keyed by ARN."
}

func (m *ResourcePoliciesModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *ResourcePoliciesModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *ResourcePoliciesModule) OpsecLevel() string {
	return "moderate"
}

func (m *ResourcePoliciesModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *ResourcePoliciesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/lambda/latest/api/API_GetPolicy.html",
		"https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html",
		"https://docs.aws.amazon.com/sns/latest/api/API_GetTopicAttributes.html",
		"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html",
	}
}

func (m *ResourcePoliciesModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "resource-type",
			Description: "AWS resource type (e.g., AWS::S3::Bucket, AWS::Lambda::Function)",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "profile",
			Description: "AWS profile name",
			Type:        "string",
		},
		{
			Name:        "profile-dir",
			Description: "AWS profile directory",
			Type:        "string",
		},
		{
			Name:        "region",
			Description: "AWS region (default: us-east-1)",
			Type:        "string",
			Default:     "us-east-1",
		},
	}
}

func (m *ResourcePoliciesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get parameters
	resourceType, ok := cfg.Args["resource-type"].(string)
	if !ok || resourceType == "" {
		return nil, fmt.Errorf("resource-type parameter is required")
	}

	// Validate resource type
	supportedTypes := m.supportedResourceTypes()
	isSupported := false
	for _, supported := range supportedTypes {
		if resourceType == supported {
			isSupported = true
			break
		}
	}
	if !isSupported {
		return nil, fmt.Errorf("unsupported resource type: %s. Supported types: %v", resourceType, supportedTypes)
	}

	// Get AWS config parameters
	profile, _ := cfg.Args["profile"].(string)
	profileDir, _ := cfg.Args["profile-dir"].(string)
	region, _ := cfg.Args["region"].(string)
	if region == "" {
		region = "us-east-1"
	}

	// Build opts slice for GetAWSCfg
	var opts []*types.Option
	if profileDir != "" {
		opts = append(opts, &types.Option{
			Name:  "profile-dir",
			Value: profileDir,
		})
	}

	awsCfg, err := helpers.GetAWSCfg(region, profile, opts, "moderate")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Get resources using CloudControl
	resources, err := m.listResources(cfg.Context, awsCfg, resourceType)
	if err != nil {
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}

	// Collect policies for each resource
	policyMap := make(map[string]any)
	for _, resource := range resources {
		policy, err := m.getResourcePolicy(cfg.Context, awsCfg, resourceType, resource)
		if err != nil {
			// Log error but continue with other resources
			if cfg.Verbose {
				fmt.Fprintf(cfg.Output, "Warning: failed to get policy for %s: %v\n", resource, err)
			}
			continue
		}
		if policy != nil {
			policyMap[resource] = policy
		}
	}

	// Build result
	return []plugin.Result{
		{
			Data: policyMap,
			Metadata: map[string]any{
				"module":        "resource-policies",
				"platform":      "aws",
				"resource_type": resourceType,
				"policy_count":  len(policyMap),
			},
		},
	}, nil
}

func (m *ResourcePoliciesModule) supportedResourceTypes() []string {
	return []string{
		"AWS::S3::Bucket",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::Lambda::Function",
		"AWS::EFS::FileSystem",
		"AWS::ElasticSearch::Domain",
	}
}

func (m *ResourcePoliciesModule) listResources(ctx context.Context, awsCfg aws.Config, resourceType string) ([]string, error) {
	client := cloudcontrol.NewFromConfig(awsCfg)

	input := &cloudcontrol.ListResourcesInput{
		TypeName: aws.String(resourceType),
	}

	var resources []string
	paginator := cloudcontrol.NewListResourcesPaginator(client, input)

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list resources: %w", err)
		}

		for _, resource := range output.ResourceDescriptions {
			if resource.Identifier != nil {
				resources = append(resources, *resource.Identifier)
			}
		}
	}

	return resources, nil
}

func (m *ResourcePoliciesModule) getResourcePolicy(ctx context.Context, awsCfg aws.Config, resourceType, identifier string) (any, error) {
	switch resourceType {
	case "AWS::S3::Bucket":
		return m.getS3BucketPolicy(ctx, awsCfg, identifier)
	case "AWS::SNS::Topic":
		return m.getSNSTopicPolicy(ctx, awsCfg, identifier)
	case "AWS::SQS::Queue":
		return m.getSQSQueuePolicy(ctx, awsCfg, identifier)
	case "AWS::Lambda::Function":
		return m.getLambdaFunctionPolicy(ctx, awsCfg, identifier)
	case "AWS::EFS::FileSystem":
		return m.getEFSFileSystemPolicy(ctx, awsCfg, identifier)
	case "AWS::ElasticSearch::Domain":
		return m.getElasticsearchDomainPolicy(ctx, awsCfg, identifier)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}
}

func (m *ResourcePoliciesModule) getS3BucketPolicy(ctx context.Context, awsCfg aws.Config, bucketName string) (any, error) {
	client := s3.NewFromConfig(awsCfg)
	output, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, err
	}
	return output.Policy, nil
}

func (m *ResourcePoliciesModule) getSNSTopicPolicy(ctx context.Context, awsCfg aws.Config, topicArn string) (any, error) {
	client := sns.NewFromConfig(awsCfg)
	output, err := client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
		TopicArn: aws.String(topicArn),
	})
	if err != nil {
		return nil, err
	}
	if policy, ok := output.Attributes["Policy"]; ok {
		return policy, nil
	}
	return nil, nil
}

func (m *ResourcePoliciesModule) getSQSQueuePolicy(ctx context.Context, awsCfg aws.Config, queueUrl string) (any, error) {
	client := sqs.NewFromConfig(awsCfg)
	output, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       aws.String(queueUrl),
		AttributeNames: []sqstypes.QueueAttributeName{"Policy"},
	})
	if err != nil {
		return nil, err
	}
	if policy, ok := output.Attributes["Policy"]; ok {
		return policy, nil
	}
	return nil, nil
}

func (m *ResourcePoliciesModule) getLambdaFunctionPolicy(ctx context.Context, awsCfg aws.Config, functionName string) (any, error) {
	client := lambda.NewFromConfig(awsCfg)
	output, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{
		FunctionName: aws.String(functionName),
	})
	if err != nil {
		return nil, err
	}
	return output.Policy, nil
}

func (m *ResourcePoliciesModule) getEFSFileSystemPolicy(ctx context.Context, awsCfg aws.Config, fileSystemId string) (any, error) {
	client := efs.NewFromConfig(awsCfg)
	output, err := client.DescribeFileSystemPolicy(ctx, &efs.DescribeFileSystemPolicyInput{
		FileSystemId: aws.String(fileSystemId),
	})
	if err != nil {
		return nil, err
	}
	return output.Policy, nil
}

func (m *ResourcePoliciesModule) getElasticsearchDomainPolicy(ctx context.Context, awsCfg aws.Config, domainName string) (any, error) {
	client := elasticsearchservice.NewFromConfig(awsCfg)
	output, err := client.DescribeElasticsearchDomain(ctx, &elasticsearchservice.DescribeElasticsearchDomainInput{
		DomainName: aws.String(domainName),
	})
	if err != nil {
		return nil, err
	}
	if output.DomainStatus != nil && output.DomainStatus.AccessPolicies != nil {
		return output.DomainStatus.AccessPolicies, nil
	}
	return nil, nil
}
