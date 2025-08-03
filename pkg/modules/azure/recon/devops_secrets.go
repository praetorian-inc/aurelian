package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AzureDevOpsSecrets = chain.NewModule(
	cfg.NewMetadata(
		"Azure DevOps Secret Scanner",
		"Scans Azure DevOps organizations for secrets in repositories, variable groups, pipelines, and service endpoints using NoseyParker.",
	).WithProperties(map[string]any{
		"id":          "devops-secrets",
		"platform":    "azure",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}),
).WithLinks(
	azure.NewAzureDevOpsAuthLink,
	azure.NewAzureDevOpsProjectDiscoveryLink,
	azure.NewAzureDevOpsRepoScanLink,
	azure.NewAzureDevOpsVariableGroupsLink,
	azure.NewAzureDevOpsPipelinesLink,
	azure.NewAzureDevOpsServiceEndpointsLink,
).WithConfigs(
	cfg.WithArg("devops-pat", ""),
	cfg.WithArg("devops-org", ""),
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewNPFindingsConsoleOutputter,
)

func init() {
	registry.Register("azure", "recon", "devops-secrets", *AzureDevOpsSecrets)
}
