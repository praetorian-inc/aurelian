package stages

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func AzureGetEnvironmentSummaryStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan *helpers.AzureEnvironmentDetails {
	logger := logs.NewStageLogger(ctx, opts, "GetAzureEnvironmentSummaryStage")
	out := make(chan *helpers.AzureEnvironmentDetails)

	go func() {
		defer close(out)

		// Get credentials
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			logger.Error("Failed to get Azure credentials", slog.String("error", err.Error()))
			return
		}

		// Create ARG client
		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		for subscription := range in {
			// Get tenant and subscription details first
			subDetails, err := helpers.GetSubscriptionDetails(ctx, cred, subscription)
			if err != nil {
				// Skip subscription if there's any error - messages already handled in GetSubscriptionDetails
				continue
			}

			tenantName, tenantID, err := helpers.GetTenantDetails(ctx, cred)
			if err != nil {
				logger.Debug("Could not get tenant details - using default values",
					slog.String("subscription", subscription))
				tenantName = "Unknown"
				tenantID = "Unknown"
			}

			// Get resource summary using ARG
			response, err := argClient.GetResourceSummaryByType(ctx, subscription)
			if err != nil {
				logger.Error("Failed to get resource summary",
					slog.String("subscription", subscription),
					slog.String("error", err.Error()))
				continue
			}

			// Process the response
			resourceMap, err := helpers.ProcessQueryResponse(response)
			if err != nil {
				logger.Error("Failed to process query response",
					slog.String("subscription", subscription),
					slog.String("error", err.Error()))
				continue
			}

			// Convert map to slice
			var resources []*helpers.ResourceCount
			for resourceType, count := range resourceMap {
				resources = append(resources, &helpers.ResourceCount{
					ResourceType: resourceType,
					Count:        count,
				})
			}

			// Sort resources by type
			sort.Slice(resources, func(i, j int) bool {
				return resources[i].ResourceType < resources[j].ResourceType
			})

			// Create environment details
			var stateStr string
			if subDetails.State != nil {
				stateStr = string(*subDetails.State)
			} else {
				stateStr = "Unknown"
			}

			env := &helpers.AzureEnvironmentDetails{
				TenantName:       tenantName,
				TenantID:         tenantID,
				SubscriptionID:   *subDetails.SubscriptionID,
				SubscriptionName: *subDetails.DisplayName,
				State:            stateStr,
				Tags:             subDetails.Tags,
				Resources:        resources,
			}

			out <- env
		}
	}()

	return out
}

// Stage for getting detailed Azure resource information
func AzureListAllStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan *types.AzureResourceDetails {
	logger := logs.NewStageLogger(ctx, opts, "GetAzureListAllStage")
	out := make(chan *types.AzureResourceDetails)
	workersCount, _ := strconv.Atoi(options.GetOptionByName("workers", opts).Value)

	go func() {
		defer close(out)

		// Get credentials
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			logger.Error("Failed to get Azure credentials", slog.String("error", err.Error()))
			return
		}

		// Create ARG client
		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		var wg sync.WaitGroup
		subscriptionChan := make(chan string)
		resultsChan := make(chan *types.AzureResourceDetails)

		// Start workers
		for i := 0; i < workersCount; i++ {
			wg.Add(1)
			go func(workerNum int) {
				defer wg.Done()
				logger.Info(fmt.Sprintf("Starting worker %d", workerNum))

				for subscription := range subscriptionChan {
					// Get subscription and tenant details
					subDetails, err := helpers.GetSubscriptionDetails(ctx, cred, subscription)
					if err != nil {
						continue // Error already logged and handled in GetSubscriptionDetails
					}

					tenantName, tenantID, err := helpers.GetTenantDetails(ctx, cred)
					if err != nil {
						logger.Debug("Could not get tenant details",
							slog.Int("worker", workerNum),
							slog.String("subscription", subscription))
						tenantName = "Unknown"
						tenantID = "Unknown"
					}

					// Build ARG query for detailed resource info
					query := `Resources 
					| where subscriptionId == '` + subscription + `'
					| project id, name, type, location, resourceGroup, tags, properties = pack_all()`

					// Execute query with pagination support
					var resources []types.ResourceInfo
					err = argClient.ExecutePaginatedQuery(ctx, query, &helpers.ARGQueryOptions{
						Subscriptions: []string{subscription},
					}, func(response *armresourcegraph.ClientResourcesResponse) error {
						// Process each page of results
						for _, row := range response.Data.([]interface{}) {
							item := row.(map[string]interface{})

							resourceInfo := types.ResourceInfo{
								ID:            item["id"].(string),
								Name:          item["name"].(string),
								Type:          item["type"].(string),
								Location:      item["location"].(string),
								ResourceGroup: item["resourceGroup"].(string),
							}

							// Handle tags
							if tags, ok := item["tags"].(map[string]interface{}); ok {
								resourceInfo.Tags = make(map[string]*string)
								for k, v := range tags {
									if v != nil {
										vStr := fmt.Sprintf("%v", v)
										resourceInfo.Tags[k] = &vStr
									}
								}
							}

							// Handle properties
							if props, ok := item["properties"].(map[string]interface{}); ok {
								resourceInfo.Properties = props
							}

							resources = append(resources, resourceInfo)
						}
						return nil
					})

					if err != nil {
						logger.Error("Failed to query resources",
							slog.Int("worker", workerNum),
							slog.String("subscription", subscription),
							slog.String("error", err.Error()))
						continue
					}

					result := &types.AzureResourceDetails{
						SubscriptionID:   subscription,
						SubscriptionName: *subDetails.DisplayName,
						TenantID:         tenantID,
						TenantName:       tenantName,
						Resources:        resources,
					}

					select {
					case resultsChan <- result:
						logger.Debug(fmt.Sprintf("Worker %d processed %d resources for subscription %s",
							workerNum, len(resources), subscription))
					case <-ctx.Done():
						return
					}
				}
			}(i)
		}

		// Feed subscriptions to workers
		go func() {
			for subscription := range in {
				select {
				case subscriptionChan <- subscription:
				case <-ctx.Done():
					return
				}
			}
			close(subscriptionChan)
		}()

		// Wait for all workers to complete
		go func() {
			wg.Wait()
			close(resultsChan)
		}()

		// Forward results
		for result := range resultsChan {
			select {
			case out <- result:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out
}

// AzureGetRoleAssignmentsStage enumerates role assignments across management groups, subscriptions, and resource groups
func AzureGetRoleAssignmentsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []*types.RoleAssignmentDetails {
	logger := logs.NewStageLogger(ctx, opts, "GetAzureRoleAssignmentsStage")
	out := make(chan []*types.RoleAssignmentDetails)
	workersCount, _ := strconv.Atoi(options.GetOptionByName("workers", opts).Value)

	go func() {
		defer close(out)
		var wg sync.WaitGroup
		subscriptionChan := make(chan string, workersCount)
		resultsChan := make(chan []*types.RoleAssignmentDetails)

		// Start workers
		for i := 0; i < workersCount; i++ {
			wg.Add(1)
			go func(workerNum int) {
				defer wg.Done()
				logger.Info(fmt.Sprintf("Starting worker %d", workerNum))

				for subscription := range subscriptionChan {
					logger.Info(fmt.Sprintf("Worker %d processing subscription: %s", workerNum, subscription))

					// Get Azure credentials
					cred, err := azidentity.NewDefaultAzureCredential(nil)
					if err != nil {
						logger.Error(fmt.Sprintf("Worker %d failed to get Azure credential: %v", workerNum, err))
						continue
					}

					assignments := make([]*types.RoleAssignmentDetails, 0)

					// Get subscription details first to ensure we have access
					logger.Debug("Getting subscription details", slog.Int("worker", workerNum), slog.String("subscription", subscription))
					subDetails, err := helpers.GetSubscriptionDetails(ctx, cred, subscription)
					if err != nil {
						logger.Error(fmt.Sprintf("Worker %d failed to get subscription details for %s: %v", workerNum, subscription, err))
						continue
					}

					// Try to get management group assignments
					logger.Info(fmt.Sprintf("Worker %d attempting to get management group assignments for %s", workerNum, subscription))
					mgmtClient, err := armmanagementgroups.NewClient(cred, &arm.ClientOptions{})
					if err == nil {
						mgmtAssignments, err := helpers.GetMgmtGroupRoleAssignments(ctx, mgmtClient, subscription)
						if err != nil {
							logger.Error(fmt.Sprintf("Worker %d failed to get management group assignments: %v", workerNum, err))
						} else {
							logger.Info(fmt.Sprintf("Worker %d found %d management group assignments", workerNum, len(mgmtAssignments)))
							if len(mgmtAssignments) > 0 {
								assignments = append(assignments, mgmtAssignments...)
							}
						}
					}

					// Get subscription level assignments
					logger.Info(fmt.Sprintf("Worker %d getting subscription level assignments for %s", workerNum, subscription))
					authClient, err := armauthorization.NewRoleAssignmentsClient(subscription, cred, &arm.ClientOptions{})
					if err != nil {
						logger.Error(fmt.Sprintf("Worker %d failed to create authorization client: %v", workerNum, err))
						continue
					}

					subAssignments, err := helpers.GetSubscriptionRoleAssignments(ctx, authClient, subscription, *subDetails.DisplayName)
					if err != nil {
						logger.Error(fmt.Sprintf("Worker %d failed to get subscription assignments: %v", workerNum, err))
					} else {
						logger.Info(fmt.Sprintf("Worker %d found %d subscription level assignments", workerNum, len(subAssignments)))
						if len(subAssignments) > 0 {
							assignments = append(assignments, subAssignments...)
						}
					}

					// Get resource group level assignments
					logger.Info(fmt.Sprintf("Worker %d getting resource group level assignments for %s", workerNum, subscription))
					resourceClient, err := armresources.NewClient(subscription, cred, &arm.ClientOptions{})
					if err != nil {
						logger.Error(fmt.Sprintf("Worker %d failed to create resources client: %v", workerNum, err))
						continue
					}

					rgAssignments, err := helpers.GetResourceGroupRoleAssignments(ctx, resourceClient, authClient, subscription, *subDetails.DisplayName)
					if err != nil {
						logger.Error(fmt.Sprintf("Worker %d failed to get resource group assignments: %v", workerNum, err))
					} else {
						logger.Info(fmt.Sprintf("Worker %d found %d resource group level assignments", workerNum, len(rgAssignments)))
						if len(rgAssignments) > 0 {
							assignments = append(assignments, rgAssignments...)
						}
					}

					logger.Info(fmt.Sprintf("Worker %d found total of %d assignments for subscription %s", workerNum, len(assignments), subscription))
					if len(assignments) > 0 {
						resultsChan <- assignments
					}
				}
				logger.Info(fmt.Sprintf("Worker %d finished processing", workerNum))
			}(i)
		}

		// Feed subscriptions to workers
		go func() {
			for subscription := range in {
				logger.Info(fmt.Sprintf("Processing subscription: %s", subscription))
				select {
				case subscriptionChan <- subscription:
				case <-ctx.Done():
					return
				}
			}
			close(subscriptionChan)
		}()

		// Wait for all workers to complete
		go func() {
			wg.Wait()
			close(resultsChan)
		}()

		// Forward results
		for assignments := range resultsChan {
			select {
			case out <- assignments:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out
}

// AzureFormatRoleAssignmentsOutput formats role assignments into JSON and Markdown
func AzureFormatRoleAssignmentsOutput(ctx context.Context, opts []*types.Option, in <-chan []*types.RoleAssignmentDetails) <-chan types.Result {
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
