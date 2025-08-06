package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", AwsListAllResources.Metadata().Properties()["id"].(string), *AwsListAllResources)
}

var AwsListAllResources = chain.NewModule(
	cfg.NewMetadata(
		"List All Resources",
		"List resources in an AWS account using CloudControl API. Supports 'full' scan for all resources or 'summary' scan for key services.",
	).WithProperties(map[string]any{
		"id":          "list-all",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/Welcome.html",
			"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
		},
	}),
).WithLinks(
	aws.NewAwsResourceTypeGeneratorLink,
	cloudcontrol.NewAWSCloudControl,
	aws.NewAwsResourceAggregatorLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	cfg.NewParam[string]("scan-type", "Scan type - 'full' for all resources or 'summary' for key services").
		WithDefault("full").
		WithShortcode("s"),
).WithInputParam(
	options.AwsProfile(),
).WithInputParam(
	options.AwsRegions(),
).WithInputParam(
	cfg.NewParam[string]("filename", "Base filename for output").
		WithDefault("").
		WithShortcode("f"),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "list-all"),
).WithAutoRun()