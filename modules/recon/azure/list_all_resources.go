package reconaz

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AzureListAllMetadata = modules.Metadata{
	Id:          "list-all",
	Name:        "List All Resources",
	Description: "List all Azure resources across subscriptions with complete details",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

var AzureListAllOptions = []*types.Option{
	&types.Option{
		Name:        "subscription",
		Short:       "s",
		Description: "Azure subscription ID or 'all' to scan all accessible subscriptions",
		Required:    true,
		Type:        types.String,
		Value:       "",
	},
	&types.Option{
		Name:        "workers",
		Short:       "w",
		Description: "Number of concurrent workers for processing resources",
		Required:    false,
		Type:        types.Int,
		Value:       "5",
	},
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
		subscriptions, err := helpers.ListSubscriptions(context.Background(), opts)
		if err != nil {
			slog.Error("Failed to list subscriptions: %v", err)
			return nil, nil, err
		}

		message.Info("Found %d subscriptions", len(subscriptions))
		for _, sub := range subscriptions {
			message.Info("Found subscription: %s", sub)
		}

		return stages.Generator(subscriptions), pipeline, nil
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
