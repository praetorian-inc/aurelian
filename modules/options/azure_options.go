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
	ValueList:   []string{"all"},
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

var azureAcceptedTypes = []string{
	"all",
	"Microsoft.Compute/virtualMachines",
	"Microsoft.Web/sites",
}

var AzureResourceTypesOpt = types.Option{
	Name:        "resource-types",
	Short:       "r",
	Description: fmt.Sprintf("Azure resource types to scan (supported: %s)", strings.Join(azureAcceptedTypes, ", ")),
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile(`(?i)^(Microsoft\.[A-Za-z]+/[A-Za-z]+|ALL)$`),
	ValueList:   azureAcceptedTypes,
}
