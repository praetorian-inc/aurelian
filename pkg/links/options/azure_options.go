package options

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
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
	Description: "Directory containing ARG query templates (replaces embedded templates when specified)",
	Required:    false,
	Type:        types.String,
	Value:       "", // Empty means use embedded templates
}

func AzureSubscription() plugin.Parameter {
	return plugin.NewParam[[]string](
		"subscription",
		"The Azure subscription to use. Can be a subscription ID or 'all'.",
		plugin.WithShortcode("s"),
		plugin.WithRequired(),
	)
}

func AzureTemplateDir() plugin.Parameter {
	return plugin.NewParam[string]("template-dir", "Directory containing Azure ARG templates (replaces embedded templates)",
		plugin.WithShortcode("t"),
	)
}

func AzureArgCategory() plugin.Parameter {
	return plugin.NewParam[string]("category", "Category of Azure ARG templates to use",
		plugin.WithShortcode("c"),
	)
}

// Azure DevOps parameters for Janus framework
func AzureDevOpsPAT() plugin.Parameter {
	return plugin.NewParam[string]("devops-pat", "Azure DevOps Personal Access Token with read access",
		plugin.WithShortcode("p"),
		plugin.WithRequired(),
	)
}

func AzureDevOpsOrganization() plugin.Parameter {
	return plugin.NewParam[string]("devops-org", "Azure DevOps organization name",
		plugin.WithShortcode("o"),
		plugin.WithRequired(),
	)
}

func AzureDevOpsProject() plugin.Parameter {
	return plugin.NewParam[string]("devops-project", "Azure DevOps project name (optional, defaults to all projects)",
		plugin.WithShortcode("j"),
	)
}

func AzureResourceSecretsTypes() plugin.Parameter {
	return plugin.NewParam[[]string]("resource-types", "Azure resource types to scan for secrets",
		plugin.WithShortcode("r"),
		plugin.WithDefault([]string{"all"}),
	)
}

func AzureWorkerCount() plugin.Parameter {
	return plugin.NewParam[int]("workers", "Number of concurrent workers for processing",
		plugin.WithShortcode("w"),
		plugin.WithDefault(5),
	)
}

func AzureConditionalAccessFile() plugin.Parameter {
	return plugin.NewParam[string]("conditional-access-file", "Path to JSON file containing conditional access policies")
}

func AzureLLMAPIKey() plugin.Parameter {
	return plugin.NewParam[string]("llm-api-key", "API key for LLM provider",
		plugin.WithRequired(),
	)
}

func AzureLLMAPIKeyOptional() plugin.Parameter {
	return plugin.NewParam[string]("llm-api-key", "API key for LLM provider (required when --enable-llm-analysis is true)")
}

func AzureLLMProvider() plugin.Parameter {
	return plugin.NewParam[string]("llm-provider", "LLM provider to use for analysis",
		plugin.WithDefault("anthropic"),
	)
}

func AzureLLMModel() plugin.Parameter {
	return plugin.NewParam[string]("llm-model", "LLM model to use for analysis",
		plugin.WithDefault("claude-opus-4-1-20250805"),
	)
}


func AzureLLMOutputTokens() plugin.Parameter {
	return plugin.NewParam[int]("llm-output-tokens", "Maximum output tokens for LLM analysis",
		plugin.WithDefault(32000),
	)
}

func AzureEnableLLMAnalysis() plugin.Parameter {
	return plugin.NewParam[bool]("enable-llm-analysis", "Enable LLM analysis of conditional access policies",
		plugin.WithDefault(false),
	)
}

func AzureResourceID() plugin.Parameter {
	return plugin.NewParam[[]string]("azure-resource-id", "Azure resource ID in full format (/subscriptions/.../resourceGroups/.../providers/...)",
		plugin.WithShortcode("i"),
		plugin.WithRequired(),
	)
}

func AzureDisableEnrichment() plugin.Parameter {
	return plugin.NewParam[bool]("disable-enrichment", "Disable enrichment of resources with security testing commands",
		plugin.WithDefault(false),
	)
}

// AzureReconBaseOptions provides common options for Azure reconnaissance modules
func AzureReconBaseOptions() []plugin.Parameter {
	return []plugin.Parameter{
		AzureSubscription(),
		AzureWorkerCount(),
		OutputDir(),
	}
}
