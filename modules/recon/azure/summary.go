package reconaz

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AzureSummaryMetadata = modules.Metadata{
	Id:          "summary",
	Name:        "Summary",
	Description: "Summarize Azure resources",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

var AzureSummaryOptions = []*types.Option{
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
		Description: "Number of concurrent workers for processing subscriptions",
		Required:    false,
		Type:        types.Int,
		Value:       "5",
	},
	options.WithDefaultValue(
		*options.WithRequired(
			options.FileNameOpt, false),
		""),
}

var AzureSummaryOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
	op.NewMarkdownFileProvider,
}

func NewAzureSummary(opts []*types.Option) (<-chan string, stages.Stage[string, types.Result], error) {
	pipeline, err := stages.ChainStages[string, types.Result](
		stages.AzureGetEnvironmentSummaryStage,
		FormatAzureOutputToMarkdownJsonStage,
	)

	if err != nil {
		return nil, nil, err
	}

	subscriptionOpt := options.GetOptionByName("subscription", opts).Value

	if strings.EqualFold(subscriptionOpt, "all") {
		// Create context with metadata for the subscription listing
		ctx := context.WithValue(context.Background(), "metadata", AzureSummaryMetadata)
		subscriptions, err := helpers.ListSubscriptions(ctx, opts)
		if err != nil {
			slog.Error("Failed to list subscriptions", slog.String("error", err.Error()))
			return nil, nil, err
		}

		slog.Info(fmt.Sprintf("Found %d subscriptions", len(subscriptions)), slog.Int("count", len(subscriptions)))
		for _, sub := range subscriptions {
			slog.Debug("Found subscription", slog.String("subscription", sub))
		}

		return stages.Generator(subscriptions), pipeline, nil
	}

	return stages.Generator([]string{subscriptionOpt}), pipeline, nil
}

// Stage for formatting Azure environment details into both JSON and Markdown outputs
func FormatAzureOutputToMarkdownJsonStage(ctx context.Context, opts []*types.Option, in <-chan *helpers.AzureEnvironmentDetails) <-chan types.Result {
	out := make(chan types.Result)

	go func() {
		defer close(out)
		for env := range in {
			// Generate base filename
			baseFilename := ""
			providedFilename := options.GetOptionByName(options.FileNameOpt.Name, opts).Value
			if len(providedFilename) == 0 {
				timestamp := strconv.FormatInt(time.Now().Unix(), 10)
				baseFilename = fmt.Sprintf("summary-%s-%s", env.SubscriptionID, timestamp)
			} else {
				baseFilename = providedFilename + "-" + env.SubscriptionID
			}

			// Convert to EnrichedResourceDescription format for JSON
			var resources []types.EnrichedResourceDescription
			for _, rc := range env.Resources {
				resources = append(resources, types.EnrichedResourceDescription{
					Identifier: rc.ResourceType,
					TypeName:   rc.ResourceType,
					Region:     "", // Azure regions are handled differently
					AccountId:  env.SubscriptionID,
					Properties: map[string]interface{}{
						"count":    rc.Count,
						"provider": getResourceCategory(rc.ResourceType),
					},
				})
			}

			// Output JSON format
			out <- types.NewResult(
				modules.Azure,
				"summary",
				resources,
				types.WithFilename(baseFilename+".json"),
			)

			// Output markdown format
			out <- types.NewResult(
				modules.Azure,
				"summary",
				createSummaryTable(env),
				types.WithFilename(baseFilename+".md"),
			)
		}
	}()

	return out
}

// Helper function to categorize Azure resources
func getResourceCategory(resourceType string) string {
	parts := strings.Split(resourceType, "/")
	if len(parts) > 0 {
		provider := parts[0]
		provider = strings.TrimPrefix(provider, "Microsoft.")
		return provider
	}
	return resourceType
}

// Helper function to create summary table
func createSummaryTable(env *helpers.AzureEnvironmentDetails) types.MarkdownTable {
	// Create subscription overview section
	var details []string
	details = append(details, fmt.Sprintf("# Azure Subscription Summary"))
	details = append(details, fmt.Sprintf("Subscription: %s (%s)", env.SubscriptionName, env.SubscriptionID))
	details = append(details, fmt.Sprintf("Tenant: %s (%s)", env.TenantName, env.TenantID))
	if env.Tags != nil && len(env.Tags) > 0 {
		var tagStrings []string
		for k, v := range env.Tags {
			if v != nil {
				tagStrings = append(tagStrings, fmt.Sprintf("%s: %s", k, *v))
			}
		}
		if len(tagStrings) > 0 {
			details = append(details, "Tags: "+strings.Join(tagStrings, ", "))
		}
	}
	details = append(details, "")

	// Group resources by category
	categories := make(map[string]int)
	for _, rc := range env.Resources {
		category := getResourceCategory(rc.ResourceType)
		categories[category] += rc.Count
	}

	// Sort categories
	var categoryNames []string
	for category := range categories {
		categoryNames = append(categoryNames, category)
	}
	sort.Strings(categoryNames)

	// Create table
	table := &types.MarkdownTable{
		TableHeading: strings.Join(details, "\n"),
		Headers:      []string{"Resource Category", "Count"},
		Rows:         make([][]string, 0),
	}

	totalCount := 0
	for _, category := range categoryNames {
		count := categories[category]
		table.Rows = append(table.Rows, []string{
			category,
			fmt.Sprintf("%d", count),
		})
		totalCount += count
	}

	// Add total row
	table.Rows = append(table.Rows, []string{"Total", fmt.Sprintf("%d", totalCount)})

	return *table
}
