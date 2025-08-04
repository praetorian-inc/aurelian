package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
	"github.com/praetorian-inc/janus-framework/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/links/general"
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
	}).WithChainInputParam(
		options.AzureSubscription().Name(),
	),
).WithConfigs(
	cfg.WithArg("category", "secrets"),
).WithLinks(
	general.NewResourceTypePreprocessor(&azure.AzureFindSecretsLink{}),
	azure.NewARGTemplateLoaderLink,
	azure.NewARGTemplateQueryLink,
	azure.NewAzureFindSecretsLink,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, cfg.WithArg("continue_piping", true)),
).WithOutputters(
	output.NewJSONOutputter,
	outputters.NewNPFindingsConsoleOutputter,
).WithInputParam(
	options.AzureResourceSecretsTypes(),
).WithInputParam(
	options.AzureArgCategory(),
)