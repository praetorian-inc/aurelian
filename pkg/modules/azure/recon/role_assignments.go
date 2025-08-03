package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("azure", "recon", AzureRoleAssignments.Metadata().Properties()["id"].(string), *AzureRoleAssignments)
}

var AzureRoleAssignments = chain.NewModule(
	cfg.NewMetadata(
		"Role Assignments",
		"Enumerate role assignments across all Azure scopes including management groups, subscriptions, and resources",
	).WithProperties(map[string]any{
		"id":          "role-assignments",
		"platform":    "azure",
		"opsec_level": "stealth",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://learn.microsoft.com/en-us/azure/role-based-access-control/overview",
			"https://learn.microsoft.com/en-us/azure/governance/management-groups/overview",
		},
	}),
).WithLinks(
	azure.NewAzureSubscriptionGeneratorLink,
	azure.NewAzureRoleAssignmentsCollectorLink,
	azure.NewAzureRoleAssignmentsOutputFormatterLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewRuntimeMarkdownOutputter,
).WithInputParam(
	options.AzureSubscription(),
).WithAutoRun()