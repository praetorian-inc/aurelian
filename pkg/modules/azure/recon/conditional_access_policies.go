package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AzureConditionalAccessPolicies = chain.NewModule(
	cfg.NewMetadata(
		"Conditional Access Policies",
		"Retrieve and document Azure Conditional Access policies with human-readable formatting, resolving UUIDs to names for users, groups, and applications. Optionally analyze policies using LLM.",
	).WithProperties(map[string]any{
		"id":          "conditional-access-policies",
		"platform":    "azure",
		"opsec_level": "stealth",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies",
			"https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy",
			"https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers",
			"https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications",
		},
	}),
).WithLinks(
	azure.NewAzureConditionalAccessCollectorLink,
	azure.NewAzureConditionalAccessResolverLink,
	azure.NewAzureConditionalAccessOutputFormatterLink,
	azure.NewAzureConditionalAccessLLMAnalyzer,
	azure.NewAzureConditionalAccessAnalysisOutputFormatterLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.AzureEnableLLMAnalysis(),
	options.AzureLLMAPIKeyOptional(),
	options.AzureLLMProvider(),
	options.AzureLLMModel(),
).WithConfigs(
	cfg.WithArg("module-name", "conditional-access-policies"),
).WithAutoRun()

func init() {
	registry.Register("azure", "recon", "conditional-access-policies", *AzureConditionalAccessPolicies)
}