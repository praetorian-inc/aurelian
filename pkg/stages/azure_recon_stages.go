package stages

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// Stage for getting Azure environment summary
func GetAzureEnvironmentSummaryStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan *helpers.AzureEnvironmentDetails {
	out := make(chan *helpers.AzureEnvironmentDetails)

	go func() {
		defer close(out)
		for subscription := range in {
			env, err := helpers.GetEnvironmentDetails(ctx, subscription, opts)
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get environment details for subscription %s: %v", subscription, err))
				continue
			}
			out <- env
		}
	}()

	return out
}

// Stage for getting detailed Azure resource information
func GetAzureListAllStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan *types.AzureResourceDetails {
	out := make(chan *types.AzureResourceDetails)
	workersCount, _ := strconv.Atoi(types.GetOptionByName("workers", opts).Value)

	go func() {
		defer close(out)

		var wg sync.WaitGroup
		subscriptionChan := make(chan string)

		// Start workers
		for i := 0; i < workersCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for subscription := range subscriptionChan {
					// Get Azure credentials
					cred, err := azidentity.NewDefaultAzureCredential(nil)
					if err != nil {
						logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get Azure credential for subscription %s: %v", subscription, err))
						continue
					}

					// Initialize the resources client
					client, err := armresources.NewClient(subscription, cred, nil)
					if err != nil {
						logs.ConsoleLogger().Error(fmt.Sprintf("Failed to create resources client for subscription %s: %v", subscription, err))
						continue
					}

					// Get subscription and tenant details
					subDetails, err := helpers.GetSubscriptionDetails(ctx, cred, subscription)
					if err != nil {
						logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get subscription details for %s: %v", subscription, err))
						continue
					}

					tenantID, tenantName, err := helpers.GetTenantDetails(ctx, cred)
					if err != nil {
						logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get tenant details for subscription %s: %v", subscription, err))
						continue
					}

					// Initialize result structure
					result := &types.AzureResourceDetails{
						SubscriptionID:   subscription,
						SubscriptionName: *subDetails.DisplayName,
						TenantID:         tenantID,
						TenantName:       tenantName,
						Resources:        make([]types.ResourceInfo, 0),
					}

					// List all resources in the subscription
					pager := client.NewListPager(nil)

					for pager.More() {
						page, err := pager.NextPage(ctx)
						if err != nil {
							logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get next page for subscription %s: %v", subscription, err))
							continue
						}

						for _, resource := range page.Value {
							resourceInfo := types.ResourceInfo{
								ID:            *resource.ID,
								Name:          *resource.Name,
								Type:          *resource.Type,
								Location:      *resource.Location,
								ResourceGroup: helpers.ExtractResourceGroup(*resource.ID),
								Tags:          resource.Tags,
								Properties:    make(map[string]interface{}),
							}

							// Add all available properties based on detail level
							if resource.Properties != nil {
								if props, ok := resource.Properties.(map[string]interface{}); ok {
									resourceInfo.Properties = props
								}
							}

							result.Resources = append(result.Resources, resourceInfo)
						}
					}

					out <- result
				}
			}()
		}

		// Feed subscriptions to workers
		for subscription := range in {
			subscriptionChan <- subscription
		}
		close(subscriptionChan)

		wg.Wait()
	}()

	return out
}

// GetAzureRoleAssignmentsStage enumerates role assignments across management groups, subscriptions, and resource groups
func GetAzureRoleAssignmentsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []*types.RoleAssignmentDetails {
	out := make(chan []*types.RoleAssignmentDetails)
	workersCount, _ := strconv.Atoi(types.GetOptionByName("workers", opts).Value)

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
				logs.ConsoleLogger().Info(fmt.Sprintf("Starting worker %d", workerNum))

				for subscription := range subscriptionChan {
					logs.ConsoleLogger().Info(fmt.Sprintf("Worker %d processing subscription: %s", workerNum, subscription))

					// Get Azure credentials
					cred, err := azidentity.NewDefaultAzureCredential(nil)
					if err != nil {
						logs.ConsoleLogger().Error(fmt.Sprintf("Worker %d failed to get Azure credential: %v", workerNum, err))
						continue
					}

					assignments := make([]*types.RoleAssignmentDetails, 0)

					// Get subscription details first to ensure we have access
					logs.ConsoleLogger().Info(fmt.Sprintf("Worker %d getting subscription details for %s", workerNum, subscription))
					subDetails, err := helpers.GetSubscriptionDetails(ctx, cred, subscription)
					if err != nil {
						logs.ConsoleLogger().Error(fmt.Sprintf("Worker %d failed to get subscription details for %s: %v", workerNum, subscription, err))
						continue
					}

					// Try to get management group assignments
					logs.ConsoleLogger().Info(fmt.Sprintf("Worker %d attempting to get management group assignments for %s", workerNum, subscription))
					mgmtClient, err := armmanagementgroups.NewClient(cred, &arm.ClientOptions{})
					if err == nil {
						mgmtAssignments, err := helpers.GetMgmtGroupRoleAssignments(ctx, mgmtClient, subscription)
						if err != nil {
							logs.ConsoleLogger().Error(fmt.Sprintf("Worker %d failed to get management group assignments: %v", workerNum, err))
						} else {
							logs.ConsoleLogger().Info(fmt.Sprintf("Worker %d found %d management group assignments", workerNum, len(mgmtAssignments)))
							if len(mgmtAssignments) > 0 {
								assignments = append(assignments, mgmtAssignments...)
							}
						}
					}

					// Get subscription level assignments
					logs.ConsoleLogger().Info(fmt.Sprintf("Worker %d getting subscription level assignments for %s", workerNum, subscription))
					authClient, err := armauthorization.NewRoleAssignmentsClient(subscription, cred, &arm.ClientOptions{})
					if err != nil {
						logs.ConsoleLogger().Error(fmt.Sprintf("Worker %d failed to create authorization client: %v", workerNum, err))
						continue
					}

					subAssignments, err := helpers.GetSubscriptionRoleAssignments(ctx, authClient, subscription, *subDetails.DisplayName)
					if err != nil {
						logs.ConsoleLogger().Error(fmt.Sprintf("Worker %d failed to get subscription assignments: %v", workerNum, err))
					} else {
						logs.ConsoleLogger().Info(fmt.Sprintf("Worker %d found %d subscription level assignments", workerNum, len(subAssignments)))
						if len(subAssignments) > 0 {
							assignments = append(assignments, subAssignments...)
						}
					}

					// Get resource group level assignments
					logs.ConsoleLogger().Info(fmt.Sprintf("Worker %d getting resource group level assignments for %s", workerNum, subscription))
					resourceClient, err := armresources.NewClient(subscription, cred, &arm.ClientOptions{})
					if err != nil {
						logs.ConsoleLogger().Error(fmt.Sprintf("Worker %d failed to create resources client: %v", workerNum, err))
						continue
					}

					rgAssignments, err := helpers.GetResourceGroupRoleAssignments(ctx, resourceClient, authClient, subscription, *subDetails.DisplayName)
					if err != nil {
						logs.ConsoleLogger().Error(fmt.Sprintf("Worker %d failed to get resource group assignments: %v", workerNum, err))
					} else {
						logs.ConsoleLogger().Info(fmt.Sprintf("Worker %d found %d resource group level assignments", workerNum, len(rgAssignments)))
						if len(rgAssignments) > 0 {
							assignments = append(assignments, rgAssignments...)
						}
					}

					logs.ConsoleLogger().Info(fmt.Sprintf("Worker %d found total of %d assignments for subscription %s", workerNum, len(assignments), subscription))
					if len(assignments) > 0 {
						resultsChan <- assignments
					}
				}
				logs.ConsoleLogger().Info(fmt.Sprintf("Worker %d finished processing", workerNum))
			}(i)
		}

		// Feed subscriptions to workers
		go func() {
			for subscription := range in {
				logs.ConsoleLogger().Info(fmt.Sprintf("Processing subscription: %s", subscription))
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
			providedFilename := types.GetOptionByName(options.FileNameOpt.Name, opts).Value
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
