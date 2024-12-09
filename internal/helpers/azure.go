package helpers

import (
	"context"
	"fmt"
	"os"
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
func GetSubscriptionDetails(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) (*armsubscriptions.Subscription, error) {
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
func GetEnvironmentDetails(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) (*AzureEnvironmentDetails, error) {
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

	return &AzureEnvironmentDetails{
		TenantName:       tenantName,
		TenantID:         tenantID,
		SubscriptionID:   *sub.SubscriptionID,
		SubscriptionName: *sub.DisplayName,
		State:            *sub.State,
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

// CreateFilePath creates a file path for Azure resources
func CreateFilePath(service, subscription, command, location, resource string) string {
	return fmt.Sprintf("azure%s%s%s%s%s%s-%s-%s.json",
		string(os.PathSeparator),
		service,
		string(os.PathSeparator),
		subscription,
		string(os.PathSeparator),
		command,
		location,
		resource)
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
