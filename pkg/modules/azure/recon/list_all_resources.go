package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
)

func init() {
	registry.Register("azure", "recon", AzureListAllResources.Metadata().Properties()["id"].(string), *AzureListAllResources)
}

var AzureListAllResources = chain.NewModule(
	cfg.NewMetadata(
		"List All Resources",
		"List all Azure resources across subscriptions with complete details including identifier. This might take a while for large subscriptions.",
	).WithProperties(map[string]any{
		"id":          "list-all",
		"platform":    "azure",
		"opsec_level": "stealth",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
			"https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language",
		},
	}),
).WithLinks(
	azure.NewAzureSubscriptionGeneratorLink,
	azure.NewAzureResourceListerLink,
	azure.NewAzureResourceAggregatorLink,
).WithOutputters(
	output.NewJSONOutputter,
).WithAutoRun()