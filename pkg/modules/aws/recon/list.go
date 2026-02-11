package recon

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSListResourcesModule{})
}

// AWSListResourcesModule lists resources by type using Cloud Control API
type AWSListResourcesModule struct{}

func (m *AWSListResourcesModule) ID() string                { return "list" }
func (m *AWSListResourcesModule) Name() string              { return "AWS List Resources" }
func (m *AWSListResourcesModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSListResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSListResourcesModule) OpsecLevel() string        { return "moderate" }
func (m *AWSListResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSListResourcesModule) Description() string {
	return "List resources in an AWS account using Cloud Control API."
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

	accountID, err := helpers.GetAccountId(awsCfg)
	if err != nil {
		accountID = ""
	}

	client := cloudcontrol.NewFromConfig(awsCfg)

	resources, err := cclist.ListByType(cfg.Context, client, resourceType, accountID, region)
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
