package helpers

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/organization"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// Common Azure locations
var AzureLocations = []string{
	"eastus",
	"eastus2",
	"westus",
	"westus2",
	"centralus",
	"northeurope",
	"westeurope",
	"southeastasia",
	"eastasia",
	"japaneast",
	"japanwest",
	"australiaeast",
	"australiasoutheast",
	"southcentralus",
	"northcentralus",
	"brazilsouth",
	"centralindia",
	"southindia",
	"westindia",
}

// ResourceCount holds the count for each Azure resource type
type ResourceCount struct {
	ResourceType string
	Count        int
}

// AzureEnvironmentDetails holds all Azure environment information
type AzureEnvironmentDetails struct {
	TenantName       string
	TenantID         string
	SubscriptionID   string
	SubscriptionName string
	State            string
	Tags             map[string]*string
	Resources        []*ResourceCount
}

// GetAzureCredentials returns Azure credentials using DefaultAzureCredential
func GetAzureCredentials(opts []*types.Option) (*azidentity.DefaultAzureCredential, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %v", err)
	}
	return cred, nil
}

// GetSubscriptionDetails gets details about an Azure subscription
func GetSubscriptionDetails(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) (*armsubscriptions.ClientGetResponse, error) {
	subsClient, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscriptions client: %v", err)
	}

	sub, err := subsClient.Get(ctx, subscriptionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription details: %v", err)
	}

	return &sub, nil
}

// GetTenantDetails gets details about the Azure tenant
func GetTenantDetails(ctx context.Context, cred *azidentity.DefaultAzureCredential) (string, string, error) {
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create Graph client: %v", err)
	}

	org, err := graphClient.Organization().Get(ctx, &organization.OrganizationRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return "", "", fmt.Errorf("failed to get organization details: %v", err)
	}

	tenantName := "Unknown"
	tenantID := "Unknown"

	if orgValue := org.GetValue(); orgValue != nil && len(orgValue) > 0 {
		if displayName := orgValue[0].GetDisplayName(); displayName != nil {
			tenantName = *displayName
		}
		if id := orgValue[0].GetId(); id != nil {
			tenantID = *id
		}
	}

	return tenantName, tenantID, nil
}

// GetResourceClient creates a new Azure Resource Management client
func GetResourceClient(cred *azidentity.DefaultAzureCredential, subscriptionID string) (*armresources.Client, error) {
	client, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource client: %v", err)
	}
	return client, nil
}

// CountResources counts Azure resources by type
func CountResources(ctx context.Context, client *armresources.Client) ([]*ResourceCount, error) {
	var resourcesCount []*ResourceCount
	pager := client.NewListPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get next page of resources: %v", err)
		}

		for _, resource := range page.Value {
			resourcesCount = addResourceCount(resourcesCount, *resource.Type)
		}
	}

	return resourcesCount, nil
}

// addResourceCount adds or updates a resource count (private helper)
func addResourceCount(resourcesCount []*ResourceCount, resourceType string) []*ResourceCount {
	for _, rc := range resourcesCount {
		if rc.ResourceType == resourceType {
			rc.Count++
			return resourcesCount
		}
	}

	resourcesCount = append(resourcesCount, &ResourceCount{
		ResourceType: resourceType,
		Count:        1,
	})
	return resourcesCount
}

// GetEnvironmentDetails gets all Azure environment details
func GetEnvironmentDetails(ctx context.Context, subscriptionID string, opts []*types.Option) (*AzureEnvironmentDetails, error) {
	// Get credentials
	cred, err := GetAzureCredentials(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %v", err)
	}

	// Get subscription details
	sub, err := GetSubscriptionDetails(ctx, cred, subscriptionID)
	if err != nil {
		return nil, err
	}

	// Get tenant details
	tenantName, tenantID, err := GetTenantDetails(ctx, cred)
	if err != nil {
		return nil, err
	}

	// Get resource counts
	client, err := GetResourceClient(cred, subscriptionID)
	if err != nil {
		return nil, err
	}

	resources, err := CountResources(ctx, client)
	if err != nil {
		return nil, err
	}

	// Convert State to string, handling the pointer
	var stateStr string
	if sub.State != nil {
		stateStr = string(*sub.State)
	} else {
		stateStr = "Unknown"
	}

	return &AzureEnvironmentDetails{
		TenantName:       tenantName,
		TenantID:         tenantID,
		SubscriptionID:   *sub.SubscriptionID,
		SubscriptionName: *sub.DisplayName,
		State:            stateStr,
		Tags:             sub.Tags,
		Resources:        resources,
	}, nil
}

// ParseLocationsOption parses the locations option string
func ParseLocationsOption(locationsOpt string) ([]string, error) {
	if locationsOpt == "ALL" {
		return AzureLocations, nil
	}

	locations := strings.Split(locationsOpt, ",")
	for _, location := range locations {
		if !IsValidLocation(location) {
			return nil, fmt.Errorf("invalid location: %s", location)
		}
	}
	return locations, nil
}

// IsValidLocation checks if a location is valid
func IsValidLocation(location string) bool {
	for _, validLocation := range AzureLocations {
		if strings.EqualFold(location, validLocation) {
			return true
		}
	}
	return false
}

// HandleAzureError logs Azure-specific errors with appropriate context
func HandleAzureError(err error, operation string, resourceID string) {
	if err != nil {
		logs.ConsoleLogger().Error(fmt.Sprintf("Azure operation '%s' failed for resource '%s': %v",
			operation,
			resourceID,
			err))
	}
}

// ListSubscriptions returns all subscriptions accessible to the user
func ListSubscriptions(ctx context.Context, opts []*types.Option) ([]string, error) {
	// Use the existing helper function to get credentials
	cred, err := GetAzureCredentials(opts)
	if err != nil {
		logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get Azure credentials: %v", err))
		return nil, fmt.Errorf("failed to get Azure credentials: %v", err)
	}

	subsClient, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		logs.ConsoleLogger().Error(fmt.Sprintf("Failed to create subscriptions client: %v", err))
		return nil, fmt.Errorf("failed to create subscriptions client: %v", err)
	}

	var subscriptionIDs []string
	pager := subsClient.NewListPager(nil)

	logs.ConsoleLogger().Info("Starting to list subscriptions...")

	pageCount := 0
	for pager.More() {
		pageCount++
		logs.ConsoleLogger().Info(fmt.Sprintf("Fetching page %d of subscriptions...", pageCount))

		page, err := pager.NextPage(ctx)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get page %d: %v", pageCount, err))
			return nil, fmt.Errorf("failed to list subscriptions: %v", err)
		}

		if page.Value == nil {
			logs.ConsoleLogger().Warn(fmt.Sprintf("Page %d returned nil value", pageCount))
			continue
		}

		logs.ConsoleLogger().Info(fmt.Sprintf("Processing page %d, found %d subscriptions",
			pageCount, len(page.Value)))

		for i, sub := range page.Value {
			if sub.SubscriptionID == nil {
				logs.ConsoleLogger().Warn(fmt.Sprintf("Subscription at index %d has nil ID", i))
				continue
			}

			state := "Unknown"
			if sub.State != nil {
				state = string(*sub.State)
			}

			name := "Unknown"
			if sub.DisplayName != nil {
				name = *sub.DisplayName
			}

			logs.ConsoleLogger().Info(fmt.Sprintf("Found subscription: ID=%s, Name=%s, State=%s",
				*sub.SubscriptionID,
				name,
				state))

			subscriptionIDs = append(subscriptionIDs, *sub.SubscriptionID)
		}

		// Check if there's another page
		if pager.More() {
			logs.ConsoleLogger().Info("More pages available")
		} else {
			logs.ConsoleLogger().Info("No more pages available")
		}
	}

	if len(subscriptionIDs) == 0 {
		logs.ConsoleLogger().Error("No accessible subscriptions found. This could be due to insufficient permissions")
		return nil, fmt.Errorf("no accessible subscriptions found")
	}

	logs.ConsoleLogger().Info(fmt.Sprintf("Total subscriptions found: %d", len(subscriptionIDs)))
	logs.ConsoleLogger().Info("Summary of all found subscriptions:")
	for i, subID := range subscriptionIDs {
		logs.ConsoleLogger().Info(fmt.Sprintf("%d. %s", i+1, subID))
	}

	return subscriptionIDs, nil
}

func ExtractResourceGroup(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// GetMgmtGroupRoleAssignments retrieves role assignments for all management groups
func GetMgmtGroupRoleAssignments(ctx context.Context, client *armmanagementgroups.Client, subscription string) ([]*types.RoleAssignmentDetails, error) {
	assignments := make([]*types.RoleAssignmentDetails, 0)

	// Create role definitions client for looking up role names
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get Azure credential for role definitions: %v", err))
	}
	roleDefClient, err := armauthorization.NewRoleDefinitionsClient(cred, &arm.ClientOptions{})
	if err != nil {
		logs.ConsoleLogger().Error(fmt.Sprintf("Failed to create role definitions client: %v", err))
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list management groups: %v", err)
		}

		for _, group := range page.Value {
			// Create authorization client
			authClient, err := armauthorization.NewRoleAssignmentsClient(subscription, cred, &arm.ClientOptions{})
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Failed to create authorization client for mgmt group: %v", err))
				continue
			}

			// Get assignments for this management group
			mgmtAssignmentPager := authClient.NewListForScopePager(*group.ID, &armauthorization.RoleAssignmentsClientListForScopeOptions{})
			for mgmtAssignmentPager.More() {
				assignmentPage, err := mgmtAssignmentPager.NextPage(ctx)
				if err != nil {
					logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get assignments for mgmt group %s: %v", *group.ID, err))
					continue
				}

				for _, assignment := range assignmentPage.Value {
					// Get role name if possible
					roleName := ""
					if roleDefClient != nil {
						props := assignment.Properties
						if props != nil && props.RoleDefinitionID != nil {
							roleName, err = getRoleDefinition(ctx, roleDefClient, *props.RoleDefinitionID)
							if err != nil {
								logs.ConsoleLogger().Debug(fmt.Sprintf("Could not get role name: %v", err))
							}
						}
					}

					details := &types.RoleAssignmentDetails{
						ID:               *assignment.ID,
						Name:             *assignment.Name,
						PrincipalID:      *assignment.Properties.PrincipalID,
						PrincipalType:    getAssignmentPrincipalType(assignment.Properties),
						RoleDefinitionID: *assignment.Properties.RoleDefinitionID,
						RoleDisplayName:  roleName,
						Scope:            *assignment.Properties.Scope,
						ScopeType:        "ManagementGroup",
						ScopeDisplayName: *group.Name,
						SubscriptionID:   subscription,
						Properties:       make(map[string]interface{}),
					}
					assignments = append(assignments, details)
				}
			}
		}
	}

	return assignments, nil
}

// GetSubscriptionRoleAssignments retrieves role assignments at the subscription level
func GetSubscriptionRoleAssignments(ctx context.Context, client *armauthorization.RoleAssignmentsClient, subscriptionID, subscriptionName string) ([]*types.RoleAssignmentDetails, error) {
	assignments := make([]*types.RoleAssignmentDetails, 0)

	// Get role definition client to look up role names
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get Azure credential for role definitions: %v", err))
	}
	roleDefClient, err := armauthorization.NewRoleDefinitionsClient(cred, &arm.ClientOptions{})
	if err != nil {
		logs.ConsoleLogger().Error(fmt.Sprintf("Failed to create role definitions client: %v", err))
	}

	// Get subscription role assignments at scope
	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)
	pager := client.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list subscription assignments: %v", err)
		}

		for _, assignment := range page.Value {
			// Get role name if possible
			roleName := ""
			if roleDefClient != nil && assignment.Properties != nil && assignment.Properties.RoleDefinitionID != nil {
				roleName, err = getRoleDefinition(ctx, roleDefClient, *assignment.Properties.RoleDefinitionID)
				if err != nil {
					logs.ConsoleLogger().Debug(fmt.Sprintf("Could not get role name: %v", err))
				}
			}

			details := &types.RoleAssignmentDetails{
				ID:               *assignment.ID,
				Name:             *assignment.Name,
				PrincipalID:      *assignment.Properties.PrincipalID,
				PrincipalType:    getAssignmentPrincipalType(assignment.Properties),
				RoleDefinitionID: *assignment.Properties.RoleDefinitionID,
				RoleDisplayName:  roleName,
				Scope:            *assignment.Properties.Scope,
				ScopeType:        "Subscription",
				ScopeDisplayName: subscriptionName,
				SubscriptionID:   subscriptionID,
				SubscriptionName: subscriptionName,
				Properties:       make(map[string]interface{}),
			}
			assignments = append(assignments, details)
		}
	}

	return assignments, nil
}

// GetResourceRoleAssignments retrieves role assignments for all resources in a subscription
func GetResourceRoleAssignments(ctx context.Context, resourceClient *armresources.Client, authClient *armauthorization.RoleAssignmentsClient, subscriptionID, subscriptionName string) ([]*types.RoleAssignmentDetails, error) {
	assignments := make([]*types.RoleAssignmentDetails, 0)

	// Get role definition client to look up role names
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get Azure credential for role definitions: %v", err))
		return nil, err
	}
	roleDefClient, err := armauthorization.NewRoleDefinitionsClient(cred, &arm.ClientOptions{})
	if err != nil {
		logs.ConsoleLogger().Error(fmt.Sprintf("Failed to create role definitions client: %v", err))
		return nil, err
	}

	// List all resources first
	pager := resourceClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list resources: %v", err)
		}

		for _, resource := range page.Value {
			if resource == nil || resource.ID == nil {
				continue
			}
			// Get role assignments for this resource
			scope := *resource.ID

			// List assignments at resource scope
			assignmentPager := authClient.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{})
			for assignmentPager.More() {
				assignmentPage, err := assignmentPager.NextPage(ctx)
				if err != nil {
					logs.ConsoleLogger().Error(fmt.Sprintf("Failed to get assignments for resource %s: %v", *resource.ID, err))
					continue
				}

				for _, assignment := range assignmentPage.Value {
					if assignment == nil || assignment.Properties == nil {
						continue
					}

					// Get role name if possible
					roleName := ""
					if roleDefClient != nil && assignment.Properties.RoleDefinitionID != nil {
						roleName, err = getRoleDefinition(ctx, roleDefClient, *assignment.Properties.RoleDefinitionID)
						if err != nil {
							logs.ConsoleLogger().Debug(fmt.Sprintf("Could not get role name: %v", err))
						}
					}

					details := &types.RoleAssignmentDetails{
						ID:               *assignment.ID,
						Name:             *assignment.Name,
						PrincipalID:      *assignment.Properties.PrincipalID,
						PrincipalType:    getAssignmentPrincipalType(assignment.Properties),
						RoleDefinitionID: *assignment.Properties.RoleDefinitionID,
						RoleDisplayName:  roleName,
						Scope:            *assignment.Properties.Scope,
						ScopeType:        "Resource",
						ScopeDisplayName: *resource.Name,
						SubscriptionID:   subscriptionID,
						SubscriptionName: subscriptionName,
						Properties:       make(map[string]interface{}),
					}
					assignments = append(assignments, details)
				}
			}
		}
	}

	return assignments, nil
}

// getRoleDefinition gets the display name for a role definition
func getRoleDefinition(ctx context.Context, client *armauthorization.RoleDefinitionsClient, roleDefID string) (string, error) {
	// Parse the role definition ID to get the role name
	parts := strings.Split(roleDefID, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid role definition ID format")
	}
	roleName := parts[len(parts)-1]

	// Get the role definition details
	def, err := client.GetByID(ctx, roleDefID, nil)
	if err != nil {
		return roleName, err
	}

	if def.Properties != nil && def.Properties.RoleName != nil {
		return *def.Properties.RoleName, nil
	}

	return roleName, nil
}

// GetResourceGroupFromID extracts the resource group name from a resource ID
func GetResourceGroupFromID(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

// getAssignmentPrincipalType safely extracts the principal type from role assignment properties
func getAssignmentPrincipalType(props *armauthorization.RoleAssignmentPropertiesWithScope) string {
	// Return a default value if properties are nil
	if props == nil {
		return "Unknown"
	}

	// Try to infer from principalId format
	if props.PrincipalID != nil {
		// User format typically includes '@'
		if strings.Contains(*props.PrincipalID, "@") {
			return "User"
		}

		// GUID format checks
		if len(*props.PrincipalID) == 36 && strings.Count(*props.PrincipalID, "-") == 4 {
			// Service Principals typically have specific prefixes in Azure
			if strings.HasPrefix(strings.ToLower(*props.PrincipalID), "f") {
				return "ServicePrincipal"
			}
			// Security Groups typically have different prefixes
			if strings.HasPrefix(strings.ToLower(*props.PrincipalID), "g") {
				return "Group"
			}
			return "SecurityPrincipal" // Generic if we can't determine specifically
		}

		// Managed Identity IDs typically start with 'mi-'
		if strings.HasPrefix(*props.PrincipalID, "mi-") {
			return "ManagedIdentity"
		}
	}

	return "Unknown"
}

// GetResourceGroupRoleAssignments retrieves role assignments for all resource groups
func GetResourceGroupRoleAssignments(ctx context.Context, resourceClient *armresources.Client, authClient *armauthorization.RoleAssignmentsClient, subscriptionID, subscriptionName string) ([]*types.RoleAssignmentDetails, error) {
	const (
		maxWorkers = 25 // Maximum number of concurrent workers
		batchSize  = 50 // Process 50 resource groups at a time
	)

	var (
		assignments = make([]*types.RoleAssignmentDetails, 0)
		mu          sync.Mutex // Protects assignments slice
		wg          sync.WaitGroup
		roleCache   = &sync.Map{} // Cache for role definitions
	)

	// Get role definition client once for reuse
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %v", err)
	}
	roleDefClient, err := armauthorization.NewRoleDefinitionsClient(cred, &arm.ClientOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create role definitions client: %v", err)
	}

	// Create the resource groups client
	resourceGroupsClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource groups client: %v", err)
	}

	// Create buffered channels
	rgChan := make(chan *armresources.ResourceGroup, batchSize)
	errChan := make(chan error, maxWorkers)

	// Start worker pool with rate limiting
	rateLimiter := time.NewTicker(50 * time.Millisecond) // 20 requests per second per worker
	defer rateLimiter.Stop()

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for rg := range rgChan {
				if rg == nil || rg.ID == nil {
					continue
				}

				<-rateLimiter.C // Rate limiting

				// Process resource group with timeout
				rgCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				rgAssignments, err := processResourceGroupWithCache(rgCtx, authClient, roleDefClient, roleCache, rg, subscriptionID, subscriptionName)
				cancel()

				if err != nil {
					if strings.Contains(strings.ToLower(err.Error()), "throttl") {
						// Requeue with backoff
						time.Sleep(time.Duration(workerID+1) * 500 * time.Millisecond)
						select {
						case rgChan <- rg:
						default:
							logs.ConsoleLogger().Error(fmt.Sprintf("Failed to requeue throttled resource group %s", *rg.Name))
						}
						continue
					}
					logs.ConsoleLogger().Error(fmt.Sprintf("Worker %d failed processing resource group %s: %v", workerID, *rg.Name, err))
					continue
				}

				// Thread-safe append of assignments
				if len(rgAssignments) > 0 {
					mu.Lock()
					assignments = append(assignments, rgAssignments...)
					mu.Unlock()
					logs.ConsoleLogger().Info(fmt.Sprintf("Added %d assignments from resource group %s", len(rgAssignments), *rg.Name))
				}
			}
		}(i)
	}

	// Feed resource groups to workers
	go func() {
		defer close(rgChan)

		// List resource groups using the proper client
		pager := resourceGroupsClient.NewListPager(nil)

		logs.ConsoleLogger().Info("Starting to list resource groups...")
		rgCount := 0

		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				errChan <- fmt.Errorf("failed to list resource groups: %v", err)
				return
			}

			if len(page.Value) == 0 {
				logs.ConsoleLogger().Debug("Got empty page of resource groups")
				continue
			}

			for _, group := range page.Value {
				rgCount++
				if group == nil {
					logs.ConsoleLogger().Debug("Found nil resource group")
					continue
				}

				logs.ConsoleLogger().Debug(fmt.Sprintf("Found resource group: %s with ID: %s", *group.Name, *group.ID))

				select {
				case rgChan <- group:
					logs.ConsoleLogger().Debug(fmt.Sprintf("Queued resource group for processing: %s", *group.Name))
				case <-ctx.Done():
					return
				}
			}
		}

		logs.ConsoleLogger().Info(fmt.Sprintf("Finished listing resource groups. Total count: %d", rgCount))
	}()

	// Wait for all workers to complete
	wg.Wait()
	close(errChan)

	// Check for any errors
	select {
	case err := <-errChan:
		if err != nil {
			return nil, err
		}
	default:
	}

	logs.ConsoleLogger().Info(fmt.Sprintf("Completed processing with %d total assignments across all resource groups", len(assignments)))
	return assignments, nil
}

// processResourceGroupWithCache handles role assignments for a single resource group using role definition cache
func processResourceGroupWithCache(ctx context.Context, authClient *armauthorization.RoleAssignmentsClient, roleDefClient *armauthorization.RoleDefinitionsClient, roleCache *sync.Map, group *armresources.ResourceGroup, subscriptionID, subscriptionName string) ([]*types.RoleAssignmentDetails, error) {
	var assignments []*types.RoleAssignmentDetails

	// Get role assignments for this resource group
	scope := *group.ID

	logs.ConsoleLogger().Debug(fmt.Sprintf("Getting role assignments for resource group %s with scope %s", *group.Name, scope))

	assignmentPager := authClient.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{})

	assignmentCount := 0
	for assignmentPager.More() {
		page, err := assignmentPager.NextPage(ctx)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error getting role assignments for resource group %s: %v", *group.Name, err))
			return nil, err
		}

		if len(page.Value) == 0 {
			logs.ConsoleLogger().Debug(fmt.Sprintf("No role assignments found in page for resource group %s", *group.Name))
			continue
		}

		for _, assignment := range page.Value {
			if assignment == nil || assignment.Properties == nil {
				logs.ConsoleLogger().Debug("Found nil assignment or properties")
				continue
			}

			assignmentCount++

			// Get role name from cache or API
			roleName := ""
			if assignment.Properties.RoleDefinitionID != nil {
				if cachedName, ok := roleCache.Load(*assignment.Properties.RoleDefinitionID); ok {
					roleName = cachedName.(string)
				} else {
					roleName, err = getRoleDefinition(ctx, roleDefClient, *assignment.Properties.RoleDefinitionID)
					if err == nil && roleName != "" {
						roleCache.Store(*assignment.Properties.RoleDefinitionID, roleName)
					}
				}
			}

			details := &types.RoleAssignmentDetails{
				ID:               *assignment.ID,
				Name:             *assignment.Name,
				PrincipalID:      *assignment.Properties.PrincipalID,
				PrincipalType:    getAssignmentPrincipalType(assignment.Properties),
				RoleDefinitionID: *assignment.Properties.RoleDefinitionID,
				RoleDisplayName:  roleName,
				Scope:            *assignment.Properties.Scope,
				ScopeType:        "ResourceGroup",
				ScopeDisplayName: *group.Name,
				SubscriptionID:   subscriptionID,
				SubscriptionName: subscriptionName,
				Properties:       make(map[string]interface{}),
			}
			assignments = append(assignments, details)
		}
	}

	logs.ConsoleLogger().Debug(fmt.Sprintf("Found %d role assignments for resource group %s", assignmentCount, *group.Name))

	return assignments, nil
}
