package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AWSPublicResourcesSingle = chain.NewModule(
	cfg.NewMetadata(
		"AWS Public Resources Single",
		"Enumerate public AWS resources",
	).WithProperties(map[string]any{
		"id":          "public-resources-single",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}).
		WithChainInputParam(options.AwsResourceArn().Name()),
).WithLinks(
	general.NewSingleResourcePreprocessor(),
	aws.NewAwsPublicResources,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewERDConsoleOutputter,
).WithInputParam(
	options.AwsResourceArn(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "public-resources-single"),
)
