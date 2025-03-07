//go:build azure || azure_recon || azure_public_resources || all

package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
)

func init() {
	registry.Register("azure", "recon", "public-resources", *AzurePublicResources)
}

var AzurePublicResources = chain.NewModule(
	cfg.NewMetadata(
		"Azure Public Resources",
		"Enumerate Azure public resources",
	).WithProperty(
		"platform", "azure",
	).WithProperty(
		"opsec_level", "moderate",
	).WithProperty(
		"authors", []string{"Praetorian"},
	),
	chain.NewChain(
		aws.NewAWSCloudControl(),
	).WithOutputters(
		output.NewJSONOutputter(),
		output.NewConsoleOutputter(),
	),
)
