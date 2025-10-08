package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("azure", "recon", AzureFindSecrets.Metadata().Properties()["id"].(string), *AzureFindSecrets)
}

var AzureFindSecrets = chain.NewModule(
	cfg.NewMetadata(
		"Azure Find Secrets",
		"Enumerate Azure resources and find secrets using NoseyParker across VMs, web apps, automation accounts, key vaults, and storage accounts",
	).WithProperties(map[string]any{
		"id":          "find-secrets",
		"platform":    "azure",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
			"https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts",
		},
	}),
).WithLinks(
	azure.NewAzureSubscriptionGeneratorLink,
	azure.NewARGTemplateLoaderLink,
	azure.NewARGTemplateQueryLink,
	azure.NewAzureFindSecretsLink,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, cfg.WithArg("continue_piping", true)),
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewNPFindingsConsoleOutputter,
).WithInputParam(
	options.AzureSubscription(),
).WithInputParam(
	options.AzureResourceSecretsTypes(),
).WithInputParam(
	options.AzureArgCategory(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	cfg.NewParam[string]("category", "category of Azure ARG templates to use"),
).WithConfigs(
	cfg.WithArg("module-name", "find-secrets"),
	cfg.WithArg("category", "secrets"),
).WithAutoRun()
