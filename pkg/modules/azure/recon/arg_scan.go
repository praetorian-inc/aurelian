package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/links/azure/enricher"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AzureARGScan = chain.NewModule(
	cfg.NewMetadata(
		"Azure ARG Template Scanner with Enrichment (only runs templates with arg-scan category)",
		"Scans Azure resources using ARG templates and enriches findings with security testing commands.",
	).WithProperties(map[string]any{
		"id":          "arg-scan",
		"platform":    "azure",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}),
).WithLinks(
	// Generate subscription IDs (resolves "all" to actual subscription GUIDs)
	azure.NewAzureSubscriptionGeneratorLink,
	// Load ARG templates and create queries for each subscription
	azure.NewARGTemplateLoaderLink,
	// Execute the ARG queries and get resources
	azure.NewARGTemplateQueryLink,
	// Enrich resources with security testing commands
	enricher.NewARGEnrichmentLink,
).WithInputParam(
	options.AzureSubscription(),
).WithParams(
	options.AzureDisableEnrichment(),
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "arg-scan"),
	cfg.WithArg("category", "arg-scan"),
).WithAutoRun()

func init() {
	registry.Register("azure", "recon", "arg-scan", *AzureARGScan)
}
