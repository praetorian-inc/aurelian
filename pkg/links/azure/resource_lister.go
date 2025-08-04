package azure

import (
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AzureResourceListerLink lists all Azure resources in a subscription using ARG
type AzureResourceListerLink struct {
	*chain.Base
	wg sync.WaitGroup
}

func NewAzureResourceListerLink(configs ...cfg.Config) chain.Link {
	l := &AzureResourceListerLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureResourceListerLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureWorkerCount(),
	}
}

func (l *AzureResourceListerLink) Process(subscription string) error {
	l.Logger.Info("Listing Azure resources", "subscription", subscription)
	
	// Get credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		l.Logger.Error("Failed to get Azure credentials", "error", err)
		return err
	}
	
	// Create ARG client directly (avoiding helpers that need metadata context)
	argClient, err := armresourcegraph.NewClient(cred, &arm.ClientOptions{})
	if err != nil {
		l.Logger.Error("Failed to create ARG client", "error", err)
		return err
	}
	
	// Get subscription details directly
	subClient, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		l.Logger.Error("Failed to create subscription client", "error", err)
		return err
	}
	
	subDetails, err := subClient.Get(l.Context(), subscription, nil)
	if err != nil {
		l.Logger.Debug("Could not get subscription details", "subscription", subscription, "error", err)
	}
	
	subscriptionName := subscription
	if err == nil && subDetails.Subscription.DisplayName != nil {
		subscriptionName = *subDetails.Subscription.DisplayName
	}
	
	// Build ARG query for detailed resource info
	query := `Resources 
	| where subscriptionId == '` + subscription + `'
	| project id, name, type, location, resourceGroup, tags, properties = pack_all()`
	
	l.Logger.Debug("Executing ARG query", "subscription", subscription)
	
	// Execute query directly
	request := armresourcegraph.QueryRequest{
		Query: &query,
		Subscriptions: []*string{&subscription},
	}
	
	var resources []types.ResourceInfo
	response, err := argClient.Resources(l.Context(), request, nil)
	if err != nil {
		l.Logger.Error("Failed to execute ARG query", "subscription", subscription, "error", err)
		return err
	}
	
	// Process results
	if response.Data != nil {
		rows, ok := response.Data.([]interface{})
		if !ok {
			return fmt.Errorf("unexpected response data type")
		}
		
		for _, row := range rows {
			item, ok := row.(map[string]interface{})
			if !ok {
				continue
			}
			
			// Helper function to safely get string values
			safeGetString := func(m map[string]interface{}, key string) string {
				if v, ok := m[key]; ok && v != nil {
					return fmt.Sprintf("%v", v)
				}
				return ""
			}
			
			resourceInfo := types.ResourceInfo{
				ID:            safeGetString(item, "id"),
				Name:          safeGetString(item, "name"),
				Type:          safeGetString(item, "type"),
				Location:      safeGetString(item, "location"),
				ResourceGroup: safeGetString(item, "resourceGroup"),
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
	}
	
	l.Logger.Info("Found resources", "subscription", subscription, "count", len(resources))
	
	// Create resource details structure
	resourceDetails := &types.AzureResourceDetails{
		SubscriptionID:   subscription,
		SubscriptionName: subscriptionName,
		TenantID:         "Unknown",
		TenantName:       "Unknown",
		Resources:        resources,
	}
	
	// Convert to tabularium AzureResource format and send each resource
	for _, resource := range resources {
		// Prepare properties map
		props := make(map[string]any)
		for k, v := range resource.Properties {
			props[k] = v
		}
		props["name"] = resource.Name
		props["location"] = resource.Location
		props["resourceGroup"] = resource.ResourceGroup
		
		// Handle tags
		if resource.Tags != nil {
			tagMap := make(map[string]string)
			for k, v := range resource.Tags {
				if v != nil {
					tagMap[k] = *v
				}
			}
			props["tags"] = tagMap
		}
		
		// Create AzureResource using tabularium
		azureResource, err := model.NewAzureResource(
			resource.ID,
			subscription,
			model.CloudResourceType(resource.Type),
			props,
		)
		if err != nil {
			l.Logger.Error("Failed to create AzureResource", "resource_id", resource.ID, "error", err)
			continue
		}
		
		l.Logger.Debug("Sending Azure resource", "id", resource.ID, "type", resource.Type)
		l.Send(azureResource)
	}
	
	// Also send the complete resource details for legacy compatibility
	l.Send(resourceDetails)
	
	return nil
}