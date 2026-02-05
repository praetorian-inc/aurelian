package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSPublicResourcesModule{})
}

// AWSPublicResourcesModule finds publicly-exposed AWS resources
type AWSPublicResourcesModule struct{}

func (m *AWSPublicResourcesModule) ID() string {
	return "public-resources"
}

func (m *AWSPublicResourcesModule) Name() string {
	return "AWS Public Resources"
}

func (m *AWSPublicResourcesModule) Description() string {
	return "Enumerate public AWS resources."
}

func (m *AWSPublicResourcesModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *AWSPublicResourcesModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *AWSPublicResourcesModule) OpsecLevel() string {
	return "moderate"
}

func (m *AWSPublicResourcesModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AWSPublicResourcesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html",
	}
}

func (m *AWSPublicResourcesModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "resource-type",
			Description: "AWS resource type to check for public exposure (e.g., AWS::S3::Bucket, AWS::EC2::SecurityGroup)",
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

func (m *AWSPublicResourcesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
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

	// Get all resources of the specified type
	resources, err := m.listResources(cfg.Context, awsCfg, resourceType)
	if err != nil {
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}

	// Filter for public resources
	publicResources := m.filterPublicResources(resourceType, resources)

	return []plugin.Result{
		{
			Data: map[string]any{
				"resource_type":      resourceType,
				"region":             region,
				"total_resources":    len(resources),
				"public_resources":   len(publicResources),
				"public_resource_list": publicResources,
			},
			Metadata: map[string]any{
				"module":      "public-resources",
				"platform":    "aws",
				"opsec_level": "moderate",
			},
		},
	}, nil
}

func (m *AWSPublicResourcesModule) listResources(ctx context.Context, awsCfg aws.Config, resourceType string) ([]map[string]any, error) {
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

		for _, desc := range output.ResourceDescriptions {
			resource := map[string]any{}
			if desc.Identifier != nil {
				resource["identifier"] = *desc.Identifier
			}
			if desc.Properties != nil {
				// Parse JSON properties
				var props map[string]any
				if err := json.Unmarshal([]byte(*desc.Properties), &props); err == nil {
					resource["properties"] = props
				} else {
					resource["properties"] = *desc.Properties
				}
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

func (m *AWSPublicResourcesModule) filterPublicResources(resourceType string, resources []map[string]any) []map[string]any {
	var publicResources []map[string]any

	for _, resource := range resources {
		if m.isPublicResource(resourceType, resource) {
			publicResources = append(publicResources, resource)
		}
	}

	return publicResources
}

func (m *AWSPublicResourcesModule) isPublicResource(resourceType string, resource map[string]any) bool {
	props, ok := resource["properties"].(map[string]any)
	if !ok {
		return false
	}

	switch resourceType {
	case "AWS::S3::Bucket":
		return m.isS3BucketPublic(props)
	case "AWS::EC2::SecurityGroup":
		return m.isSecurityGroupPublic(props)
	case "AWS::RDS::DBInstance":
		return m.isRDSPublic(props)
	case "AWS::ElasticLoadBalancingV2::LoadBalancer":
		return m.isLoadBalancerPublic(props)
	default:
		// For unknown resource types, check for common public indicators
		return m.hasPublicIndicators(props)
	}
}

func (m *AWSPublicResourcesModule) isS3BucketPublic(props map[string]any) bool {
	// Check PublicAccessBlockConfiguration
	if pab, ok := props["PublicAccessBlockConfiguration"].(map[string]any); ok {
		blockPublicAcls, _ := pab["BlockPublicAcls"].(bool)
		blockPublicPolicy, _ := pab["BlockPublicPolicy"].(bool)
		ignorePublicAcls, _ := pab["IgnorePublicAcls"].(bool)
		restrictPublicBuckets, _ := pab["RestrictPublicBuckets"].(bool)

		// If any block is false, the bucket might be public
		if !blockPublicAcls || !blockPublicPolicy || !ignorePublicAcls || !restrictPublicBuckets {
			return true
		}
	}
	return false
}

func (m *AWSPublicResourcesModule) isSecurityGroupPublic(props map[string]any) bool {
	// Check for ingress rules with 0.0.0.0/0
	if ingress, ok := props["SecurityGroupIngress"].([]any); ok {
		for _, rule := range ingress {
			if ruleMap, ok := rule.(map[string]any); ok {
				if cidr, ok := ruleMap["CidrIp"].(string); ok && cidr == "0.0.0.0/0" {
					return true
				}
			}
		}
	}
	return false
}

func (m *AWSPublicResourcesModule) isRDSPublic(props map[string]any) bool {
	// Check PubliclyAccessible flag
	if publiclyAccessible, ok := props["PubliclyAccessible"].(bool); ok {
		return publiclyAccessible
	}
	return false
}

func (m *AWSPublicResourcesModule) isLoadBalancerPublic(props map[string]any) bool {
	// Check Scheme
	if scheme, ok := props["Scheme"].(string); ok {
		return strings.ToLower(scheme) == "internet-facing"
	}
	return false
}

func (m *AWSPublicResourcesModule) hasPublicIndicators(props map[string]any) bool {
	// Generic check for common public access indicators
	for key, val := range props {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "public") {
			if boolVal, ok := val.(bool); ok && boolVal {
				return true
			}
		}
		if strings.Contains(keyLower, "internetfacing") || strings.Contains(keyLower, "internet-facing") {
			return true
		}
	}
	return false
}
