package output

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureResource_ImplementsAurelianModel(t *testing.T) {
	var _ model.AurelianModel = AzureResource{}
	var _ model.AurelianModel = &AzureResource{}
}

func TestNewAzureResource(t *testing.T) {
	r := NewAzureResource(
		"sub-123",
		"Microsoft.Storage/storageAccounts",
		"/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
	)
	assert.Equal(t, "sub-123", r.SubscriptionID)
	assert.Equal(t, "Microsoft.Storage/storageAccounts", r.ResourceType)
	assert.Equal(t, "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1", r.ResourceID)
}

func TestAzureResource_JSONRoundTrip(t *testing.T) {
	r := AzureResource{
		ResourceType:   "Microsoft.Compute/virtualMachines",
		ResourceID:     "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
		SubscriptionID: "sub-123",
		ResourceGroup:  "rg",
		Location:       "westus2",
		DisplayName:    "vm1",
		Tags:           map[string]string{"env": "test"},
		Properties:     map[string]any{"vmSize": "Standard_B1ls"},
	}
	data, err := json.Marshal(r)
	require.NoError(t, err)

	var got AzureResource
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, r.ResourceType, got.ResourceType)
	assert.Equal(t, r.ResourceID, got.ResourceID)
	assert.Equal(t, r.SubscriptionID, got.SubscriptionID)
	assert.Equal(t, r.ResourceGroup, got.ResourceGroup)
	assert.Equal(t, r.Location, got.Location)
	assert.Equal(t, r.DisplayName, got.DisplayName)
	assert.Equal(t, r.Tags, got.Tags)
	assert.Equal(t, "Standard_B1ls", got.Properties["vmSize"])
}
