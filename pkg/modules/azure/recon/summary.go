package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AzureSummary = chain.NewModule(
	cfg.NewMetadata(
		"Summary",
		"Provides a count of Azure resources within a subscription without details such as identifiers. For a detailed resource list with identifiers, please use the list-all module.",
	).WithProperties(map[string]any{
		"id":          "summary",
		"platform":    "azure",
		"opsec_level": "stealth",
		"authors":     []string{"Praetorian"},
	}),
).WithLinks(
	azure.NewAzureSubscriptionGeneratorLink,
	azure.NewAzureEnvironmentDetailsCollectorLink,
	azure.NewAzureSummaryOutputFormatterLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	output.NewMarkdownOutputter,
).WithAutoRun()

func init() {
	registry.Register("azure", "recon", "summary", *AzureSummary)
}