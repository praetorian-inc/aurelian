package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/aurelian/internal/registry"
	"github.com/praetorian-inc/aurelian/pkg/links/aws"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/links/general"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", AWSPublicResources.Metadata().Properties()["id"].(string), *AWSPublicResources)
}

var AWSPublicResources = chain.NewModule(
	cfg.NewMetadata(
		"AWS Public Resources",
		"Enumerate public AWS resources",
	).WithProperties(map[string]any{
		"id":          "public-resources",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}).
		WithChainInputParam(options.AwsResourceType().Name()),
).WithLinks(
	general.NewResourceTypePreprocessor(&aws.AwsPublicResources{}),
	cloudcontrol.NewAWSCloudControl,
	aws.NewAwsPublicResources,
	aws.NewAWSPublicResourcesProcessor,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewERDConsoleOutputter,
).WithInputParam(
	options.AwsProfile(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.AwsProfile(),
	options.AwsOrgPoliciesFile(),
).WithConfigs(
	cfg.WithArg("module-name", "public-resources"),
)
