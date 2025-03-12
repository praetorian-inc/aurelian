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
	"AWS::ECR::PublicRepository",
}

var AWSPublicResources = chain.NewModule(
	cfg.NewMetadata(
		"AWS Public Resources",
		"Enumerate public AWS resources",
	).WithProperties(map[string]any{
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}).
		WithChainInputParam(options.AwsResourceType().Name()),
).WithLinks(
	aws.NewAwsPublicResources,
).WithOutputters(
	output.NewJSONOutputter,
	output.NewConsoleOutputter,
)
