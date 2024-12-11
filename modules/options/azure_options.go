package options

import (
	"regexp"

	"github.com/praetorian-inc/nebula/pkg/types"
)

var AzureSubscriptionOpt = types.Option{
	Name:        "subscription",
	Short:       "s",
	Description: "Azure subscription ID",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$"),
}

var AzureWorkerCountOpt = types.Option{
	Name:        "workers",
	Short:       "w",
	Description: "Number of concurrent workers for processing subscriptions",
	Required:    false,
	Type:        types.Int,
	Value:       "5", // Default to 5 workers
}
