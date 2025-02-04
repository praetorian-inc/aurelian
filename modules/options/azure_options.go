package options

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nebula/pkg/types"
)

var AzureSubscriptionOpt = types.Option{
	Name:        "subscription",
	Short:       "s",
	Description: "Azure subscription ID or 'all' to scan all accessible subscriptions",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile(`(?i)^([0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}|ALL)$`),
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

var AzureResourceSecretsTypesOpt = types.Option{
	Name:        "resource-types",
	Short:       "r",
	Description: fmt.Sprintf("Comma-separated list of Azure resource types to scan (supported: %s)", strings.Join(azureAcceptedSecretsTypes, ", ")),
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueList:   azureAcceptedSecretsTypes,
}
