// modules/recon/azure/arg_template_recon.go
package reconaz

import (
	"context"
	"strings"

	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AzureARGReconMetadata = modules.Metadata{
	Id:          "arg-scan",
	Name:        "Azure Resource Graph Scanner",
	Description: "Configuration review that scans Azure resources using custom Resource Graph query templates",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References: []string{
		"https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview",
		"https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language",
	},
}

// Options specific to ARG template scanning
var AzureARGReconOptions = []*types.Option{
	&options.AzureSubscriptionOpt,
	&options.AzureWorkerCountOpt,
	&options.AzureARGTemplatesDirOpt,
	options.WithDefaultValue(
		*options.WithRequired(
			options.FileNameOpt, false),
		""),
}

var AzureARGReconOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
	op.NewMarkdownFileProvider,
}

func NewAzureARGRecon(opts []*types.Option) (<-chan string, stages.Stage[string, types.Result], error) {
	pipeline, err := stages.ChainStages[string, types.Result](
		stages.AzureARGTemplateStage,
		stages.FormatARGReconOutput,
	)

	if err != nil {
		return nil, nil, err
	}

	subscriptionOpt := options.GetOptionByName(options.AzureSubscriptionOpt.Name, opts).Value

	if strings.EqualFold(subscriptionOpt, "all") {
		ctx := context.WithValue(context.Background(), "metadata", AzureARGReconMetadata)
		subscriptions, err := helpers.ListSubscriptions(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		return stages.Generator(subscriptions), pipeline, nil
	}

	return stages.Generator([]string{subscriptionOpt}), pipeline, nil
}