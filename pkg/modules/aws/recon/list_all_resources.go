package recon

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSListAllResourcesModule{})
}

// AWSListAllResourcesModule enumerates all resources using Cloud Control API
type AWSListAllResourcesModule struct{}

func (m *AWSListAllResourcesModule) ID() string {
	return "list-all"
}

func (m *AWSListAllResourcesModule) Name() string {
	return "AWS List All Resources"
}

func (m *AWSListAllResourcesModule) Description() string {
	return "List resources in an AWS account using CloudControl API. Supports 'full' scan for all resources or 'summary' scan for key services."
}

func (m *AWSListAllResourcesModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *AWSListAllResourcesModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *AWSListAllResourcesModule) OpsecLevel() string {
	return "moderate"
}

func (m *AWSListAllResourcesModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AWSListAllResourcesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/Welcome.html",
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSListAllResourcesModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "scan-type",
			Description: "Scan type - 'full' for all resources or 'summary' for key services",
			Type:        "string",
			Default:     "full",
			Shortcode:   "s",
		},
		{
			Name:        "region",
			Description: "AWS region",
			Type:        "string",
			Default:     "us-east-1",
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
	}
}

func (m *AWSListAllResourcesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get parameters
	scanType, ok := cfg.Args["scan-type"].(string)
	if !ok || scanType == "" {
		scanType = "full"
	}

	region, ok := cfg.Args["region"].(string)
	if !ok || region == "" {
		region = "us-east-1"
	}

	profile, _ := cfg.Args["profile"].(string)
	profileDir, _ := cfg.Args["profile-dir"].(string)

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

	// Get resource types to enumerate
	var resourceTypes []string
	if strings.ToLower(scanType) == "summary" {
		resourceTypes = m.getKeySummaryResourceTypes()
	} else {
		resourceTypes = m.getAllResourceTypes()
	}

	// Enumerate resources concurrently
	results, err := m.enumerateResources(cfg.Context, awsCfg, resourceTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate resources: %w", err)
	}

	return []plugin.Result{
		{
			Data: map[string]any{
				"scan_type":       scanType,
				"region":          region,
				"resource_types":  len(resourceTypes),
				"total_resources": m.countTotalResources(results),
				"resources":       results,
			},
			Metadata: map[string]any{
				"module":      "list-all",
				"platform":    "aws",
				"opsec_level": "moderate",
			},
		},
	}, nil
}

func (m *AWSListAllResourcesModule) getKeySummaryResourceTypes() []string {
	return []string{
		"AWS::EC2::Instance",
		"AWS::S3::Bucket",
		"AWS::Lambda::Function",
		"AWS::DynamoDB::Table",
		"AWS::RDS::DBInstance",
		"AWS::IAM::Role",
		"AWS::IAM::User",
		"AWS::ECS::Cluster",
		"AWS::EKS::Cluster",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
	}
}

func (m *AWSListAllResourcesModule) getAllResourceTypes() []string {
	// Comprehensive list of Cloud Control supported resource types
	return []string{
		"AWS::EC2::Instance",
		"AWS::EC2::VPC",
		"AWS::EC2::Subnet",
		"AWS::EC2::SecurityGroup",
		"AWS::EC2::Volume",
		"AWS::S3::Bucket",
		"AWS::Lambda::Function",
		"AWS::DynamoDB::Table",
		"AWS::RDS::DBInstance",
		"AWS::RDS::DBCluster",
		"AWS::IAM::Role",
		"AWS::IAM::User",
		"AWS::IAM::Policy",
		"AWS::ECS::Cluster",
		"AWS::ECS::Service",
		"AWS::EKS::Cluster",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::CloudFormation::Stack",
		"AWS::KMS::Key",
		"AWS::SecretsManager::Secret",
		"AWS::CloudWatch::Alarm",
		"AWS::ApiGateway::RestApi",
		"AWS::ApiGatewayV2::Api",
		"AWS::ElasticLoadBalancingV2::LoadBalancer",
		"AWS::AutoScaling::AutoScalingGroup",
	}
}

func (m *AWSListAllResourcesModule) enumerateResources(ctx context.Context, awsCfg aws.Config, resourceTypes []string) (map[string]any, error) {
	client := cloudcontrol.NewFromConfig(awsCfg)

	results := make(map[string]any)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errChan := make(chan error, len(resourceTypes))

	for _, resourceType := range resourceTypes {
		wg.Add(1)
		go func(rt string) {
			defer wg.Done()

			resources, err := m.listResourcesByType(ctx, client, rt)
			if err != nil {
				// Log error but continue with other resource types
				errChan <- fmt.Errorf("failed to list %s: %w", rt, err)
				return
			}

			mu.Lock()
			results[rt] = map[string]any{
				"count":     len(resources),
				"resources": resources,
			}
			mu.Unlock()
		}(resourceType)
	}

	wg.Wait()
	close(errChan)

	// Collect errors (non-fatal)
	var errors []string
	for err := range errChan {
		errors = append(errors, err.Error())
	}

	if len(errors) > 0 {
		results["errors"] = errors
	}

	return results, nil
}

func (m *AWSListAllResourcesModule) listResourcesByType(ctx context.Context, client *cloudcontrol.Client, resourceType string) ([]map[string]any, error) {
	var allResources []map[string]any
	var nextToken *string

	for {
		input := &cloudcontrol.ListResourcesInput{
			TypeName: &resourceType,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		output, err := client.ListResources(ctx, input)
		if err != nil {
			return nil, err
		}

		for _, desc := range output.ResourceDescriptions {
			resource := map[string]any{}
			if desc.Identifier != nil {
				resource["identifier"] = *desc.Identifier
			}
			if desc.Properties != nil {
				resource["properties"] = *desc.Properties
			}
			allResources = append(allResources, resource)
		}

		nextToken = output.NextToken
		if nextToken == nil {
			break
		}
	}

	return allResources, nil
}

func (m *AWSListAllResourcesModule) countTotalResources(results map[string]any) int {
	total := 0
	for key, val := range results {
		if key == "errors" {
			continue
		}
		if resourceMap, ok := val.(map[string]any); ok {
			if count, ok := resourceMap["count"].(int); ok {
				total += count
			}
		}
	}
	return total
}
