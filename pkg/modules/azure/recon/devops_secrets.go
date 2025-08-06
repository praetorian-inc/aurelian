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
	// Repository scan runs first (handles its own NoseyParker scanning)
	azure.NewAzureDevOpsRepoScanLink,
	// Then collect other data sources that need NoseyParker processing
	azure.NewAzureDevOpsVariableGroupsLink,
	azure.NewAzureDevOpsPipelinesLink,
	azure.NewAzureDevOpsServiceEndpointsLink,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, 
		cfg.WithArg("continue_piping", true)),
).WithConfigs(
	cfg.WithArg("devops-pat", ""),
	cfg.WithArg("devops-org", ""),
).WithInputParam(
	options.AzureDevOpsProject(),
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewNPFindingsConsoleOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "devops-secrets"),
).WithAutoRun()

func init() {
	registry.Register("azure", "recon", "devops-secrets", *AzureDevOpsSecrets)
}
