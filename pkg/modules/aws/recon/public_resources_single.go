package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", AWSPublicResourcesSingle.Metadata().Properties()["id"].(string), *AWSPublicResourcesSingle)
}

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
	output.NewJSONOutputter,
	//output.NewConsoleOutputter,
	outputters.NewERDConsoleOutputter,
).WithInputParam(
	options.AwsResourceArn(),
)
