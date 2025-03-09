package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

func init() {
	registry.Register("aws", "recon", "public-resources", *AWSPublicResources)
}

var PublicResourcesTypes = []string{
	"AWS::EC2::Instance",
	"AWS::CloudFormation::Stack",
}

var AWSPublicResources = chain.NewModule(
	cfg.NewMetadata(
		"AWS Public Resources",
		"Enumerate public AWS resources",
	).WithProperty(
		"platform", "aws",
	).WithProperty(
		"opsec_level", "moderate",
	).WithProperty(
		"authors", []string{"Praetorian"},
	).WithChainInputParam(options.AwsResourceType().Name()),
	chain.NewChain(
		aws.NewAwsPublicResources(),
	).WithOutputters(
		output.NewJSONOutputter(),
		output.NewConsoleOutputter(),
	),
)
