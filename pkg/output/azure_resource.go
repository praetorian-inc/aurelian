package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// AzureResource represents an Azure cloud resource discovered during scanning.
type AzureResource struct {
	model.BaseAurelianModel

	ResourceType   string            `json:"resource_type"`
	ResourceID     string            `json:"resource_id"`
	SubscriptionID string            `json:"subscription_id"`
	ResourceGroup  string            `json:"resource_group,omitempty"`
	Location       string            `json:"location,omitempty"`
	DisplayName    string            `json:"display_name,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
	Properties     map[string]any    `json:"properties,omitempty"`
}

// NewAzureResource creates an AzureResource with required fields.
func NewAzureResource(subscriptionID, resourceType, resourceID string) AzureResource {
	return AzureResource{
		SubscriptionID: subscriptionID,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
	}
}
