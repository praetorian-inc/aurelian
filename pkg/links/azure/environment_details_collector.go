package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// AzureEnvironmentDetailsCollectorLink collects Azure environment details including subscription, tenant, and resource counts
type AzureEnvironmentDetailsCollectorLink struct {
	*base.NativeAzureLink
}

func NewAzureEnvironmentDetailsCollectorLink(args map[string]any) *AzureEnvironmentDetailsCollectorLink {
	return &AzureEnvironmentDetailsCollectorLink{
		NativeAzureLink: base.NewNativeAzureLink("azure-environment-details-collector", args),
	}
}

func (l *AzureEnvironmentDetailsCollectorLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		options.AzureWorkerCount(),
	}
}

func (l *AzureEnvironmentDetailsCollectorLink) Process(ctx context.Context, input any) ([]any, error) {
	subscription, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string (subscription), got %T", input)
	}

	l.Logger().Info("Collecting Azure environment details", "subscription", subscription)

	// Get credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		l.Logger().Error("Failed to get Azure credentials", "error", err)
		return nil, err
	}

	// Get subscription details
	sub, err := l.getSubscriptionDetails(ctx, cred, subscription)
	if err != nil {
		l.Logger().Error("Failed to get subscription details", "subscription", subscription, "error", err)
		return nil, err
	}

	// Get tenant ID from subscription details (no Graph API needed)
	tenantID := "Unknown"
	tenantName := "Unknown"
	if sub.TenantID != nil {
		tenantID = *sub.TenantID
	}

	// Get resource counts
	resourceClient, err := armresources.NewClient(subscription, cred, nil)
	if err != nil {
		l.Logger().Error("Failed to create resource client", "subscription", subscription, "error", err)
		return nil, err
	}

	resources, err := l.countResources(ctx, resourceClient)
	if err != nil {
		l.Logger().Error("Failed to count resources", "subscription", subscription, "error", err)
		return nil, err
	}

	// Convert State to string, handling the pointer
	var stateStr string
	if sub.State != nil {
		stateStr = string(*sub.State)
	} else {
		stateStr = "Unknown"
	}

	envDetails := &helpers.AzureEnvironmentDetails{
		TenantName:       tenantName,
		TenantID:         tenantID,
		SubscriptionID:   *sub.SubscriptionID,
		SubscriptionName: *sub.DisplayName,
		State:            stateStr,
		Tags:             convertAzureTagsToStringMap(sub.Tags),
		Resources:        resources,
	}

	l.Logger().Info("Collected environment details",
		"subscription", envDetails.SubscriptionName,
		"subscription_id", envDetails.SubscriptionID,
		"tenant", envDetails.TenantName,
		"resource_types", len(envDetails.Resources))

	// Send the environment details to the next link
	l.Send(envDetails)

	return l.Outputs(), nil
}

// getSubscriptionDetails gets details about an Azure subscription
func (l *AzureEnvironmentDetailsCollectorLink) getSubscriptionDetails(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) (*armsubscriptions.Subscription, error) {
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscription client: %v", err)
	}

	sub, err := client.Get(ctx, subscriptionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %v", err)
	}

	return &sub.Subscription, nil
}


// countResources counts Azure resources by type
func (l *AzureEnvironmentDetailsCollectorLink) countResources(ctx context.Context, client *armresources.Client) ([]*helpers.ResourceCount, error) {
	var resourcesCount []*helpers.ResourceCount
	pager := client.NewListPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get next page of resources: %v", err)
		}

		for _, resource := range page.Value {
			resourcesCount = l.addResourceCount(resourcesCount, *resource.Type)
		}
	}

	return resourcesCount, nil
}

// addResourceCount adds or updates a resource count
func (l *AzureEnvironmentDetailsCollectorLink) addResourceCount(resourcesCount []*helpers.ResourceCount, resourceType string) []*helpers.ResourceCount {
	for _, rc := range resourcesCount {
		if rc.ResourceType == resourceType {
			rc.Count++
			return resourcesCount
		}
	}

	resourcesCount = append(resourcesCount, &helpers.ResourceCount{
		ResourceType: resourceType,
		Count:        1,
	})

	return resourcesCount
}

// convertAzureTagsToStringMap converts Azure SDK tag format to simple string map
func convertAzureTagsToStringMap(azureTags map[string]*string) map[string]string {
	if azureTags == nil {
		return nil
	}
	tags := make(map[string]string)
	for k, v := range azureTags {
		if v != nil {
			tags[k] = *v
		}
	}
	return tags
}
