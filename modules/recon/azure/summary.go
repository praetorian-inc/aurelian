package reconaz

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureSummary implements the Module interface
type AzureSummary struct {
	modules.BaseModule
}

// Module metadata
var AzureSummaryMetadata = modules.Metadata{
	Id:          "summary",
	Name:        "Summary",
	Description: "Summarize Azure resources",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

// Module options
var AzureSummaryOptions = []*types.Option{
	&options.AzureSubscriptionOpt,
	types.SetDefaultValue(
		*types.SetRequired(
			options.FileNameOpt, false),
		AzureSummaryMetadata.Id+"-"+strconv.FormatInt(time.Now().Unix(), 10)+".md"),
}

// Output providers
var AzureSummaryOutputProvders = []func(options []*types.Option) types.OutputProvider{
	op.NewMarkdownFileProvider,
}

// NewAzureSummary creates a new instance of the Azure summary module
func NewAzureSummary(opts []*types.Option) (<-chan string, stages.Stage[string, types.MarkdownTable], error) {
	pipeline, err := stages.ChainStages[string, types.MarkdownTable](
		AzureSummaryStage,
	)

	subscription := types.GetOptionByName(options.AzureSubscriptionOpt.Name, opts).Value
	return stages.Generator([]string{subscription}), pipeline, err
}

// AzureSummaryStage is the main processing stage for the module
func AzureSummaryStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.MarkdownTable {
	out := make(chan types.MarkdownTable)
	go func() {
		defer close(out)

		for subscription := range in {
			// Get credentials
			cred, err := helpers.GetAzureCredentials(opts)
			if err != nil {
				logs.ConsoleLogger().Error(err.Error())
				continue
			}

			// Get environment details
			env, err := helpers.GetEnvironmentDetails(ctx, cred, subscription)
			if err != nil {
				logs.ConsoleLogger().Error(err.Error())
				continue
			}

			// Create markdown content
			var details []string
			details = append(details, fmt.Sprintf("# Azure Environment Summary"))
			details = append(details, "")
			details = append(details, "## Environment Details")
			details = append(details, "")
			details = append(details, "### Tenant Information")
			details = append(details, fmt.Sprintf("- **Tenant Name:** %s", env.TenantName))
			details = append(details, fmt.Sprintf("- **Tenant ID:** %s", env.TenantID))
			details = append(details, "")
			details = append(details, "### Subscription Information")
			details = append(details, fmt.Sprintf("- **Subscription Name:** %s", env.SubscriptionName))
			details = append(details, fmt.Sprintf("- **Subscription ID:** %s", env.SubscriptionID))
			details = append(details, fmt.Sprintf("- **State:** %s", env.State))
			if env.Tags != nil && len(env.Tags) > 0 {
				details = append(details, "- **Tags:**")
				for k, v := range env.Tags {
					details = append(details, fmt.Sprintf("  - %s: %s", k, *v))
				}
			}
			details = append(details, "")
			details = append(details, "## Resource Summary")
			details = append(details, "")

			// Create markdown table
			table := types.MarkdownTable{
				TableHeading: strings.Join(details, "\n"),
				Headers:      []string{"Resource Type", "Count"},
				Rows:         make([][]string, 0),
			}

			// Add resources to table
			for _, rc := range env.Resources {
				row := []string{
					rc.ResourceType,
					strconv.Itoa(rc.Count),
				}
				table.Rows = append(table.Rows, row)
			}

			out <- table
		}
	}()
	return out
}
