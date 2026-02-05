package recon

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSListResourcesModule{})
}

// AWSListResourcesModule lists resources by type using Cloud Control API
type AWSListResourcesModule struct{}

func (m *AWSListResourcesModule) ID() string {
	return "list"
}

func (m *AWSListResourcesModule) Name() string {
	return "AWS List Resources"
}

func (m *AWSListResourcesModule) Description() string {
	return "List resources in an AWS account using Cloud Control API."
}

func (m *AWSListResourcesModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *AWSListResourcesModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *AWSListResourcesModule) OpsecLevel() string {
	return "moderate"
}

func (m *AWSListResourcesModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AWSListResourcesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/what-is-cloudcontrol.html",
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSListResourcesModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "resource-type",
			Description: "AWS resource type (e.g., AWS::S3::Bucket, AWS::EC2::Instance)",
			Type:        "string",
			Required:    true,
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

func (m *AWSListResourcesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get parameters
	resourceType, ok := cfg.Args["resource-type"].(string)
	if !ok || resourceType == "" {
		return nil, fmt.Errorf("resource-type parameter is required")
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

	// List resources using Cloud Control API
	resources, err := m.listResources(cfg.Context, awsCfg, resourceType)
	if err != nil {
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}

	return []plugin.Result{
		{
			Data: map[string]any{
				"resource_type":  resourceType,
				"region":         region,
				"resource_count": len(resources),
				"resources":      resources,
			},
			Metadata: map[string]any{
				"module":      "list",
				"platform":    "aws",
				"opsec_level": "moderate",
			},
		},
	}, nil
}

func (m *AWSListResourcesModule) listResources(ctx context.Context, awsCfg aws.Config, resourceType string) ([]map[string]any, error) {
	client := cloudcontrol.NewFromConfig(awsCfg)

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
			return nil, fmt.Errorf("failed to list resources of type %s: %w", resourceType, err)
		}

		// Process resource descriptions
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
