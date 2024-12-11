package helpers

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
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
