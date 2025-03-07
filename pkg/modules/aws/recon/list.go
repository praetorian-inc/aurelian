//go:build aws || aws_recon || aws_recon_find_secrets || all

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
	AwsListResources.Chain().Initialize()
	registry.Register("aws", "recon", "list", *AwsListResources)
}

var AwsListResources = chain.NewModule(
	cfg.NewMetadata(
		"AWS List Resources",
		"List resources in an AWS account using Cloud Control API.",
	).WithProperty(
		"platform", "aws",
	).WithProperty(
		"authors", []string{"Praetorian"},
	).WithProperty(
		"references", []string{
			"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/what-is-cloudcontrol.html",
			"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
		},
	).WithChainInputParam(options.AwsResourceType().Name()),
	chain.NewChain(
		aws.NewAWSCloudControl(),
	).WithOutputters(
		// output.NewConsoleOutputter(),
		output.NewJSONOutputter(),
	),
)
