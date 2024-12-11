package reconaz

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
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
		Value:       "5", // Default to 5 workers
	},
	types.SetDefaultValue(
		*types.SetRequired(
			options.FileNameOpt, false),
		op.DefaultFileName(AzureSummaryMetadata.Id, "md")),
}

// Output providers
var AzureSummaryOutputProvders = []func(options []*types.Option) types.OutputProvider{
	op.NewMarkdownFileProvider,
}

// Helper types for concurrent processing
type subscriptionResult struct {
	subscriptionID string
	table          *types.MarkdownTable
	err            error
}

// NewAzureSummary creates a new instance of the Azure summary module
func NewAzureSummary(opts []*types.Option) (<-chan string, stages.Stage[string, types.MarkdownTable], error) {
	pipeline, err := stages.ChainStages[string, types.MarkdownTable](
		AzureSummaryStage,
	)

	if err != nil {
		return nil, nil, err
	}

	subscriptionOpt := types.GetOptionByName("subscription", opts).Value

	if strings.EqualFold(subscriptionOpt, "all") {
		subscriptions, err := helpers.ListSubscriptions(context.Background(), opts)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Failed to list subscriptions: %v", err))
			return nil, nil, err
		}

		logs.ConsoleLogger().Info(fmt.Sprintf("Found %d subscriptions", len(subscriptions)))
		for _, sub := range subscriptions {
			logs.ConsoleLogger().Info(fmt.Sprintf("Found subscription: %s", sub))
		}

		return stages.Generator(subscriptions), pipeline, nil
	}

	return stages.Generator([]string{subscriptionOpt}), pipeline, err
}

// AzureSummaryStage processes subscriptions concurrently
func AzureSummaryStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.MarkdownTable {
	out := make(chan types.MarkdownTable)

	go func() {
		defer close(out)

		// Get worker count from options
		workerOpt := types.GetOptionByName("workers", opts)
		workerCount := 5 // Default worker count
		if workerOpt != nil && workerOpt.Value != "" {
			count, err := strconv.Atoi(workerOpt.Value)
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Invalid worker count: %v, using default of 5", err))
			} else {
				workerCount = count
			}
		}

		// Create job and result channels
		jobs := make(chan string, workerCount)
		results := make(chan *subscriptionResult, workerCount)

		// Start worker pool
		var wg sync.WaitGroup
		for i := 0; i < workerCount; i++ {
			wg.Add(1)
			go subscriptionWorker(ctx, opts, jobs, results, &wg)
		}

		// Submit jobs
		go func() {
			for subscription := range in {
				jobs <- subscription
			}
			close(jobs)
		}()

		// Wait for all workers to complete
		go func() {
			wg.Wait()
			close(results)
		}()

		// Collect and sort results
		var failedSubs []string
		successfulTables := make([]*types.MarkdownTable, 0)

		for result := range results {
			if result.err != nil {
				failedSubs = append(failedSubs, result.subscriptionID)
				logs.ConsoleLogger().Error(fmt.Sprintf("Failed to process subscription %s: %v",
					result.subscriptionID, result.err))
				continue
			}
			successfulTables = append(successfulTables, result.table)
		}

		// Sort tables by subscription ID for consistent output
		sort.Slice(successfulTables, func(i, j int) bool {
			return successfulTables[i].TableHeading < successfulTables[j].TableHeading
		})

		// Send successful tables
		for _, table := range successfulTables {
			out <- *table
		}

		// Send failed subscriptions table if any
		if len(failedSubs) > 0 {
			failedTable := types.MarkdownTable{
				TableHeading: "# Failed Subscriptions\nThe following subscriptions could not be processed:",
				Headers:      []string{"Subscription ID"},
				Rows:         make([][]string, 0),
			}

			for _, sub := range failedSubs {
				failedTable.Rows = append(failedTable.Rows, []string{sub})
			}

			out <- failedTable
		}
	}()

	return out
}

// Worker function for processing subscriptions
func subscriptionWorker(
	ctx context.Context,
	opts []*types.Option,
	jobs <-chan string,
	results chan<- *subscriptionResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for subscriptionID := range jobs {
		// Add timeout to context for each job
		jobCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

		result := &subscriptionResult{
			subscriptionID: subscriptionID,
		}

		// Process subscription
		env, err := helpers.GetEnvironmentDetails(jobCtx, subscriptionID, opts)
		if err != nil {
			result.err = err
			results <- result
			cancel()
			continue
		}

		// Create markdown table
		table := createMarkdownTable(env)
		result.table = table

		// Send result
		results <- result
		cancel()
	}
}

// Create markdown table from environment details
func createMarkdownTable(env *helpers.AzureEnvironmentDetails) *types.MarkdownTable {
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
			if v != nil {
				details = append(details, fmt.Sprintf("  - %s: %s", k, *v))
			}
		}
	}

	details = append(details, "")
	details = append(details, "## Resource Summary")
	details = append(details, "")

	// Sort resources for consistent output
	sort.Slice(env.Resources, func(i, j int) bool {
		return env.Resources[i].ResourceType < env.Resources[j].ResourceType
	})

	table := &types.MarkdownTable{
		TableHeading: strings.Join(details, "\n"),
		Headers:      []string{"Resource Type", "Count"},
		Rows:         make([][]string, 0),
	}

	totalCount := 0
	for _, rc := range env.Resources {
		table.Rows = append(table.Rows, []string{
			rc.ResourceType,
			fmt.Sprintf("%d", rc.Count),
		})
		totalCount += rc.Count
	}

	// Add total row
	table.Rows = append(table.Rows, []string{"Total", fmt.Sprintf("%d", totalCount)})

	return table
}
