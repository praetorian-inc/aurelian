package reconaz

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AzureListAllMetadata = modules.Metadata{
	Id:          "list-all",
	Name:        "List All Resources",
	Description: "List all Azure resources across subscriptions with complete details including identifier. This might take a while for large subscriptions.",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

var AzureListAllOptions = []*types.Option{
	options.WithDescription(
		options.AzureSubscriptionOpt,
		"Azure subscription ID or 'all' for all accessible subscriptions",
	),
	options.WithDefaultValue(
		options.AzureWorkerCountOpt,
		"5",
	),
	options.WithDefaultValue(
		*options.WithRequired(
			options.FileNameOpt, false),
		""),
}

var AzureListAllOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
	op.NewMarkdownFileProvider,
}

func NewAzureListAll(opts []*types.Option) (<-chan string, stages.Stage[string, types.Result], error) {
	pipeline, err := stages.ChainStages[string, types.Result](
		stages.AzureListAllStage,
		FormatAzureListAllOutputStage,
	)

	if err != nil {
		return nil, nil, err
	}

	subscriptionOpt := options.GetOptionByName("subscription", opts).Value

	if strings.EqualFold(subscriptionOpt, "all") {
		// Create channel for subscriptions
		subscriptionsChan := make(chan string)

		go func() {
			defer close(subscriptionsChan)

			// Create context with metadata
			ctx := context.WithValue(context.Background(), "metadata", AzureListAllMetadata)
			subscriptions, err := helpers.ListSubscriptions(ctx, opts)
			if err != nil {
				slog.Error("Failed to list subscriptions", slog.String("error", err.Error()))
				return
			}

			for _, sub := range subscriptions {
				subscriptionsChan <- sub
			}
		}()

		return subscriptionsChan, pipeline, nil
	}

	return stages.Generator([]string{subscriptionOpt}), pipeline, nil
}

// Stage for formatting Azure list-all output
func FormatAzureListAllOutputStage(ctx context.Context, opts []*types.Option, in <-chan *types.AzureResourceDetails) <-chan types.Result {
	out := make(chan types.Result)

	go func() {
		defer close(out)
		for resourceDetails := range in {
			baseFilename := ""
			providedFilename := options.GetOptionByName(options.FileNameOpt.Name, opts).Value
			if len(providedFilename) == 0 {
				timestamp := strconv.FormatInt(time.Now().Unix(), 10)
				baseFilename = fmt.Sprintf("list-all-%s-%s", resourceDetails.SubscriptionID, timestamp)
			} else {
				baseFilename = providedFilename + "-" + resourceDetails.SubscriptionID
			}

			var resources []types.EnrichedResourceDescription
			for _, resource := range resourceDetails.Resources {
				props := make(map[string]interface{})
				for k, v := range resource.Properties {
					props[k] = v
				}
				props["name"] = resource.Name
				props["tags"] = resource.Tags

				enrichedResource := types.EnrichedResourceDescription{
					Identifier: resource.ID,
					TypeName:   resource.Type,
					Region:     resource.Location,
					AccountId:  resourceDetails.SubscriptionID,
					Properties: props,
				}

				resources = append(resources, enrichedResource)
			}

			out <- types.NewResult(
				modules.Azure,
				"list-all",
				resources,
				types.WithFilename(baseFilename+".json"),
			)

			out <- types.NewResult(
				modules.Azure,
				"list-all",
				createResourceListTable(resourceDetails),
				types.WithFilename(baseFilename+".md"),
			)
		}
	}()

	return out
}

// Helper function to create resource list table
func createResourceListTable(details *types.AzureResourceDetails) types.MarkdownTable {
	var markdownContent []string
	markdownContent = append(markdownContent, fmt.Sprintf("# Azure Resources List"))
	markdownContent = append(markdownContent, fmt.Sprintf("Subscription: %s (%s)", details.SubscriptionName, details.SubscriptionID))
	markdownContent = append(markdownContent, fmt.Sprintf("Tenant: %s (%s)", details.TenantName, details.TenantID))
	markdownContent = append(markdownContent, "")

	table := &types.MarkdownTable{
		TableHeading: strings.Join(markdownContent, "\n"),
		Headers:      []string{"Resource Name", "Type", "Location", "Resource Group"},
		Rows:         make([][]string, 0),
	}

	for _, resource := range details.Resources {
		table.Rows = append(table.Rows, []string{
			resource.Name,
			resource.Type,
			resource.Location,
			resource.ResourceGroup,
		})
	}

	return *table
}
