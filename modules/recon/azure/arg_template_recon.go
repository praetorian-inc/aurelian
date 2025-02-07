// modules/recon/azure/arg_template_recon.go
package reconaz

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

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
	Description: "Scan Azure resources using custom Resource Graph query templates",
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
		FormatARGReconOutput,
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

// FormatARGReconOutput formats the scan results for output
func FormatARGReconOutput(ctx context.Context, opts []*types.Option, in <-chan *types.ARGQueryResult) <-chan types.Result {
	out := make(chan types.Result)

	go func() {
		defer close(out)

		// Group results by template
		resultsByTemplate := make(map[string][]*types.ARGQueryResult)
		for result := range in {
			resultsByTemplate[result.TemplateID] = append(resultsByTemplate[result.TemplateID], result)
		}

		// Generate base filename
		baseFilename := ""
		providedFilename := options.GetOptionByName(options.FileNameOpt.Name, opts).Value
		if len(providedFilename) == 0 {
			timestamp := strconv.FormatInt(time.Now().Unix(), 10)
			baseFilename = fmt.Sprintf("arg-findings-%s", timestamp)
		} else {
			baseFilename = providedFilename
		}

		// Output JSON format
		out <- types.NewResult(
			modules.Azure,
			"arg-scan",
			resultsByTemplate,
			types.WithFilename(baseFilename+".json"),
		)

		// Create markdown report
		table := types.MarkdownTable{
			TableHeading: fmt.Sprintf("Azure Resource Graph Scan Results\n\n"+
				"Summary\n"+
				"Total templates executed: %d\n\n"+
				"Findings by Template", len(resultsByTemplate)),
			Headers: []string{
				"Template",
				"Resource Name",
				"Resource Type",
				"Location",
				"Details",
			},
			Rows: make([][]string, 0),
		}

		// Add results to table
		for _, results := range resultsByTemplate {
			if len(results) == 0 {
				continue
			}

			// Add findings
			for _, result := range results {
				details := formatResultDetails(result.Properties)
				table.Rows = append(table.Rows, []string{
					result.Name,
					result.ResourceName,
					result.ResourceType,
					result.Location,
					details,
				})
			}
		}

		out <- types.NewResult(
			modules.Azure,
			"arg-scan",
			table,
			types.WithFilename(baseFilename+".md"),
		)
	}()

	return out
}

// Helper function to format result details
func formatResultDetails(properties map[string]interface{}) string {
	var details []string
	for k, v := range properties {
		details = append(details, fmt.Sprintf("%s: %v", k, v))
	}
	return strings.Join(details, ", ")
}