package analyze

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("azure", "analyze", AzureConditionalAccessAnalysis.Metadata().Properties()["id"].(string), *AzureConditionalAccessAnalysis)
}

var AzureConditionalAccessAnalysis = chain.NewModule(
	cfg.NewMetadata(
		"Conditional Access Analysis",
		"Analyze Azure Conditional Access policies for potential security gaps and logical conflicts using LLM analysis",
	).WithProperties(map[string]any{
		"id":          "conditional-access-analysis",
		"platform":    "azure",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
	}),
).WithLinks(
	azure.NewAzureConditionalAccessFileLoader,
	azure.NewAzureConditionalAccessLLMAnalyzer,
	azure.NewAzureConditionalAccessAnalysisOutputFormatterLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.AzureConditionalAccessFile(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.AzureConditionalAccessFile(),
	options.AzureLLMAPIKey(),
	options.AzureLLMProvider(),
	options.AzureLLMModel(),
).WithConfigs(
	cfg.WithArg("module-name", "conditional-access-analysis"),
).WithAutoRun()