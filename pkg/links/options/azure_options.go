package options

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var azureAcceptedSecretsTypes = []string{
	"all",
	"Microsoft.Compute/virtualMachines/userData",
	"Microsoft.Compute/virtualMachines/extensions",
	"Microsoft.Compute/virtualMachines/diskEncryption",
	"Microsoft.Compute/virtualMachines/tags",
	"Microsoft.Web/sites/configuration",
	"Microsoft.Web/sites/connectionStrings",
	"Microsoft.Web/sites/keys",
	"Microsoft.Web/sites/settings",
	"Microsoft.Web/sites/tags",
	"Microsoft.Automation/automationAccounts/runbooks",
	"Microsoft.Automation/automationAccounts/variables",
	"Microsoft.Automation/automationAccounts/jobs",
}

var AzureSubscriptionOpt = types.Option{
	Name:        "subscription",
	Description: "The Azure subscription to use. Can be a subscription ID or 'all'.",
	Required:    true,
	Default:     "all",
}

var AzureWorkerCountOpt = types.Option{
	Name:        "workers",
	Short:       "w",
	Description: "Number of concurrent workers for processing subscriptions",
	Required:    false,
	Type:        types.Int,
	Value:       "5", // Default to 5 workers
}

var AzureTimeoutOpt = types.Option{
	Name:        "timeout",
	Short:       "t",
	Description: "Timeout in seconds for each subscription scan",
	Required:    false,
	Type:        types.Int,
	Value:       "600", // 10 minute default timeout
}

var AzureResourceSecretsTypesOpt = types.Option{
	Name:        "resource-types",
	Short:       "r",
	Description: fmt.Sprintf("Comma-separated list of Azure resource types to scan (supported: %s)", strings.Join(azureAcceptedSecretsTypes, ", ")),
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueList:   azureAcceptedSecretsTypes,
}

// Azure DevOps PAT
var AzureDevOpsPATOpt = types.Option{
	Name:        "devops-pat",
	Short:       "d",
	Description: "Azure DevOps Personal Access Token with read access",
	Required:    true,
	Type:        types.String,
	Value:       "",
	Sensitive:   true,
}

var AzureDevOpsOrgOpt = types.Option{
	Name:        "devops-org",
	Description: "Azure DevOps organization name",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AzureDevOpsProjectOpt = types.Option{
	Name:        "devops-project",
	Description: "Azure DevOps project name",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AzureARGTemplatesDirOpt = types.Option{
	Name:        "template-dir",
	Short:       "T",
	Description: "Optional directory containing additional ARG query templates (defaults to embedded templates)",
	Required:    false,
	Type:        types.String,
	Value:       "", // Empty means use only embedded templates
}

func AzureSubscription() cfg.Param {
	return cfg.NewParam[[]string](
		"subscription",
		"The Azure subscription to use. Can be a subscription ID or 'all'.",
	).WithShortcode("s").AsRequired()
}

func AzureTemplateDir() cfg.Param {
	return cfg.NewParam[string]("template-dir", "Directory containing Azure ARG templates").
		WithShortcode("t")
}

func AzureArgCategory() cfg.Param {
	return cfg.NewParam[string]("category", "Category of Azure ARG templates to use").
		WithShortcode("c")
}
