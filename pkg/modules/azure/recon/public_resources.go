package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AzurePublicAccess = chain.NewModule(
	cfg.NewMetadata(
		"Public Resource Scanner",
		"Detects publicly accessible Azure resources including storage accounts, app services, SQL databases, VMs, and more.",
	).WithProperties(map[string]any{
		"id":       "public-resources",
		"platform": "azure",
		"authors":  []string{"Praetorian"},
	}).WithChainInputParam(options.AzureSubscription().Name()),
).WithLinks(
	azure.NewARGTemplateLoaderLink,
	azure.NewARGTemplateQueryLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewAzureResourceOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	cfg.NewParam[string]("category", "category of Azure ARG templates to use"),
).WithConfigs(
	cfg.WithArg("module-name", "public-resources"),
	cfg.WithArg("category", "Public Access"),
)

func init() {
	registry.Register("azure", "recon", "public-resources", *AzurePublicAccess)
}
