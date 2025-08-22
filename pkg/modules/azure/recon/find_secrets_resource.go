package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("azure", "recon", AzureFindSecretsResource.Metadata().Properties()["id"].(string), *AzureFindSecretsResource)
}

var AzureFindSecretsResource = chain.NewModule(
	cfg.NewMetadata(
		"Azure Find Secrets Resource",
		"Find secrets using NoseyParker for a specific Azure resource",
	).WithProperties(map[string]any{
		"id":          "find-secrets-resource",
		"platform":    "azure",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}).WithChainInputParam(
		options.AzureResourceID().Name(),
	),
).WithLinks(
	general.NewAzureResourceIDPreprocessor(),
	azure.NewAzureFindSecretsLink,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, cfg.WithArg("continue_piping", true)),
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewNPFindingsConsoleOutputter,
).WithInputParam(
	options.AzureResourceID(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "find-secrets-resource"),
)
