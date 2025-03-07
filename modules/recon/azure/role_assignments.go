package reconaz

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AzureRoleAssignmentsMetadata = modules.Metadata{
	Id:          "role-assignments",
	Name:        "Role Assignments",
	Description: "Enumerate role assignments across all Azure scopes including management groups, subscriptions, and resources",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References: []string{
		"https://learn.microsoft.com/en-us/azure/role-based-access-control/overview",
		"https://learn.microsoft.com/en-us/azure/governance/management-groups/overview",
	},
}

// Modified options to include timeout
var AzureRoleAssignmentsOptions = []*types.Option{
	options.WithDescription(
		options.AzureSubscriptionOpt,
		"Azure subscription ID or 'all' for all accessible subscriptions",
	),
	options.WithDefaultValue(
		options.AzureWorkerCountOpt,
		"5",
	),
	options.WithDefaultValue(
		options.AzureTimeoutOpt,
		"600",
	),
	options.WithDefaultValue(
		*options.WithRequired(
			options.FileNameOpt, false),
		""),
}

var AzureRoleAssignmentsOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
	op.NewMarkdownFileProvider,
}

func NewAzureRoleAssignments(opts []*types.Option) (<-chan string, stages.Stage[string, types.Result], error) {
	pipeline, err := stages.ChainStages[string, types.Result](
		stages.AzureGetRoleAssignmentsStage,
		stages.AzureFormatRoleAssignmentsOutput,
	)

	if err != nil {
		return nil, nil, err
	}

	subscriptionOpt := options.GetOptionByName("subscription", opts).Value

	if strings.EqualFold(subscriptionOpt, "all") {
		// Added context with timeout for subscription listing
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		subscriptions, err := helpers.ListSubscriptions(ctx, opts)
		if err != nil {
			return nil, nil, err
		}

		// Add prioritization logic for subscriptions
		prioritizedSubs := prioritizeSubscriptions(subscriptions)
		return stages.Generator(prioritizedSubs), pipeline, nil
	}

	return stages.Generator([]string{subscriptionOpt}), pipeline, nil
}

// Helper function to prioritize subscriptions based on their ID patterns
func prioritizeSubscriptions(subscriptions []string) []string {
	// Create buckets for different priority levels
	var highPriority, mediumPriority, lowPriority []string

	for _, sub := range subscriptions {
		switch {
		case strings.Contains(strings.ToLower(sub), "prod"):
			highPriority = append(highPriority, sub)
		case strings.Contains(strings.ToLower(sub), "dev") ||
			strings.Contains(strings.ToLower(sub), "test"):
			mediumPriority = append(mediumPriority, sub)
		default:
			lowPriority = append(lowPriority, sub)
		}
	}

	// Combine the buckets in priority order
	result := append(highPriority, mediumPriority...)
	result = append(result, lowPriority...)
	return result
}

// BatchProcessor handles processing subscriptions in smaller batches
type BatchProcessor struct {
	batchSize int
	timeout   time.Duration
	workers   int
	results   chan types.Result
}

func NewBatchProcessor(batchSize, workers int, timeout time.Duration) *BatchProcessor {
	return &BatchProcessor{
		batchSize: batchSize,
		timeout:   timeout,
		workers:   workers,
		results:   make(chan types.Result, workers),
	}
}

func (bp *BatchProcessor) ProcessBatch(ctx context.Context, subscriptions []string) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, bp.workers)

	for i := 0; i < len(subscriptions); i += bp.batchSize {
		end := i + bp.batchSize
		if end > len(subscriptions) {
			end = len(subscriptions)
		}

		batch := subscriptions[i:end]

		// Process each subscription in the batch
		for _, sub := range batch {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(subscription string) {
				defer func() {
					<-semaphore
					wg.Done()
				}()

				// Create context with timeout for this subscription
				subCtx, cancel := context.WithTimeout(ctx, bp.timeout)
				defer cancel()

				// Process single subscription with timeout
				result, err := processSingleSubscription(subCtx, subscription)
				if err != nil {
					slog.Error("Error processing subscription " + subscription + ": " + err.Error())
					return
				}

				bp.results <- result
			}(sub)
		}

		// Wait for batch to complete before moving to next batch
		wg.Wait()
	}
}

func processSingleSubscription(ctx context.Context, subscription string) (types.Result, error) {
	// Implementation of single subscription processing
	// This would move the core processing logic from the stage into this function
	// with proper context handling and retries
	return types.Result{}, nil // Placeholder
}

// FormatAzureRoleAssignmentsOutput formats role assignments into JSON and Markdown
func FormatAzureRoleAssignmentsOutput(ctx context.Context, opts []*types.Option, in <-chan []*types.RoleAssignmentDetails) <-chan types.Result {
	out := make(chan types.Result)

	go func() {
		defer close(out)

		for assignments := range in {
			if len(assignments) == 0 {
				continue
			}

			// Generate base filename
			baseFilename := ""
			providedFilename := options.GetOptionByName(options.FileNameOpt.Name, opts).Value
			if len(providedFilename) == 0 {
				timestamp := strconv.FormatInt(time.Now().Unix(), 10)
				baseFilename = fmt.Sprintf("role-assignments-%s-%s", assignments[0].SubscriptionID, timestamp)
			} else {
				baseFilename = providedFilename + "-" + assignments[0].SubscriptionID
			}

			// Format as JSON
			out <- types.NewResult(
				modules.Azure,
				"role-assignments",
				assignments,
				types.WithFilename(baseFilename+".json"),
			)

			// Format as Markdown table
			table := types.MarkdownTable{
				TableHeading: fmt.Sprintf("Azure Role Assignments\nSubscription: %s (%s)",
					assignments[0].SubscriptionName,
					assignments[0].SubscriptionID),
				Headers: []string{
					"Principal Type",
					"Principal ID",
					"Role Name",
					"Scope Type",
					"Scope Name",
				},
				Rows: make([][]string, 0, len(assignments)),
			}

			// Add rows for each assignment
			for _, assignment := range assignments {
				roleName := assignment.RoleDisplayName
				if roleName == "" {
					roleName = assignment.RoleDefinitionID
				}

				table.Rows = append(table.Rows, []string{
					assignment.PrincipalType,
					assignment.PrincipalID,
					roleName,
					assignment.ScopeType,
					assignment.ScopeDisplayName,
				})
			}

			out <- types.NewResult(
				modules.Azure,
				"role-assignments",
				table,
				types.WithFilename(baseFilename+".md"),
			)
		}
	}()

	return out
}
