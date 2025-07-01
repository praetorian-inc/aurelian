package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/links/noseyparker"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

// func init() {
// 	registry.Register("aws", "recon", AWSFindSecrets.Metadata().Properties()["id"].(string), *AWSFindSecrets)
// }

var AWSFindSecretsResource = chain.NewModule(
	cfg.NewMetadata(
		"AWS Find Secrets Resource",
		"Enumerate AWS resources and find secrets using NoseyParker for a specific resource type",
	).WithProperties(map[string]any{
		"id":          "aws-find-secrets-resource",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}).WithChainInputParam(
		options.AwsResourceArn().Name(),
	),
).WithLinks(
	general.NewSingleResourcePreprocessor(),
	aws.NewAWSFindSecrets,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, cfg.WithArg("continue_piping", true)),
).WithOutputters(
	output.NewJSONOutputter,
	output.NewConsoleOutputter,
).WithInputParam(
	options.AwsResourceType().WithDefault([]string{"all"}),
)
