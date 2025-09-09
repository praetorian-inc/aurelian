package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", AWSFindSecrets.Metadata().Properties()["id"].(string), *AWSFindSecrets)
}

var AWSFindSecrets = chain.NewModule(
	cfg.NewMetadata(
		"AWS Find Secrets",
		"Enumerate AWS resources and find secrets using NoseyParker",
	).WithProperties(map[string]any{
		"id":          "find-secrets",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}).WithChainInputParam(
		options.AwsResourceType().Name(),
	),
).WithLinks(
	general.NewResourceTypePreprocessor(&aws.AWSFindSecrets{}),
	cloudcontrol.NewAWSCloudControl,
	aws.NewAWSFindSecrets,
	aws.NewAWSResourceChainProcessor,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, cfg.WithArg("continue_piping", true)),
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewNPFindingsConsoleOutputter,
).WithInputParam(
	options.AwsResourceType().WithDefault([]string{"all"}),
).WithInputParam(
	options.AwsProfile(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "find-secrets"),
).WithStrictness(chain.Lax)
