package output

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestAzureResource_ImplementsAurelianModel(t *testing.T) {
	t.Parallel()

	var _ model.AurelianModel = AzureResource{}
	var _ model.AurelianModel = &AzureResource{}
}

func TestNewAzureResource(t *testing.T) {
	t.Parallel()

	r := NewAzureResource(
		"sub-123",
		"Microsoft.Storage/storageAccounts",
		"/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
	)
	assert.Equal(t, "sub-123", r.SubscriptionID)
	assert.Equal(t, "Microsoft.Storage/storageAccounts", r.ResourceType)
	assert.Equal(t, "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1", r.ResourceID)
}
