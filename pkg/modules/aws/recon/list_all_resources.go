package recon

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSListAllResourcesModule{})
}

// AWSListAllResourcesModule enumerates all resources using Cloud Control API
type AWSListAllResourcesModule struct{}

func (m *AWSListAllResourcesModule) ID() string                { return "list-all" }
func (m *AWSListAllResourcesModule) Name() string              { return "AWS List All Resources" }
func (m *AWSListAllResourcesModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSListAllResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSListAllResourcesModule) OpsecLevel() string        { return "moderate" }
func (m *AWSListAllResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSListAllResourcesModule) Description() string {
	return "List resources in an AWS account using CloudControl API. Supports 'full' scan for all resources or 'summary' scan for key services."
}

func (m *AWSListAllResourcesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/Welcome.html",
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSListAllResourcesModule) SupportedResourceTypes() []string {
	return resourcetypes.GetAll()
}

func (m *AWSListAllResourcesModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("scan-type", "Scan type - 'full' for all resources or 'summary' for key services",
			plugin.WithDefault("full"),
			plugin.WithShortcode("s"),
			plugin.WithEnum("full", "summary"),
		),
		options.AwsRegions(),
		options.AwsProfile(),
		options.AwsProfileDir(),
		plugin.NewParam[int]("concurrency", "Maximum concurrent CloudControl API requests",
			plugin.WithDefault(5),
		),
	}
}

func (m *AWSListAllResourcesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	params := plugin.NewParameters(m.Parameters()...)

	for k, v := range cfg.Args {
		params.Set(k, v)
	}

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("parameter validation failed: %w", err)
	}

	scanType := params.String("scan-type")
	region := params.String("region")
	profile := params.String("profile")
	profileDir := params.String("profile-dir")
	concurrency := params.Int("concurrency")

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

	var resourceTypes []string
	if strings.ToLower(scanType) == "summary" {
		resourceTypes = resourcetypes.GetSummary()
	} else {
		resourceTypes = resourcetypes.GetAll()
	}

	client := cloudcontrol.NewFromConfig(awsCfg)

	results, err := cclist.ListAll(cfg.Context, client, resourceTypes, accountID, region, concurrency)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate resources: %w", err)
	}

	return []plugin.Result{
		{
			Data: results,
			Metadata: map[string]any{
				"module":      "list-all",
				"platform":    "aws",
				"opsec_level": "moderate",
			},
		},
	}, nil
}
