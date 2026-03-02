package resourcegraph

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseARGRow_ValidRow(t *testing.T) {
	row := map[string]any{
		"id":            "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
		"name":          "vm-1",
		"type":          "microsoft.compute/virtualmachines",
		"location":      "eastus",
		"resourceGroup": "rg",
		"tags":          map[string]any{"env": "prod", "team": "infra"},
		"properties":    map[string]any{"vmId": "abc-123", "hardwareProfile": map[string]any{"vmSize": "Standard_B2s"}},
	}

	resource, err := parseARGRow(row, "sub-1")
	require.NoError(t, err)
	assert.Equal(t, "sub-1", resource.SubscriptionID)
	assert.Equal(t, "microsoft.compute/virtualmachines", resource.ResourceType)
	assert.Equal(t, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1", resource.ResourceID)
	assert.Equal(t, "vm-1", resource.DisplayName)
	assert.Equal(t, "eastus", resource.Location)
	assert.Equal(t, "rg", resource.ResourceGroup)
	assert.Equal(t, map[string]string{"env": "prod", "team": "infra"}, resource.Tags)
	assert.Equal(t, "abc-123", resource.Properties["vmId"])
}

func TestParseARGRow_NilTags(t *testing.T) {
	row := map[string]any{
		"id":            "/subscriptions/sub-1/providers/Microsoft.Storage/storageAccounts/sa1",
		"name":          "sa1",
		"type":          "microsoft.storage/storageaccounts",
		"location":      "westus2",
		"resourceGroup": "rg2",
		"tags":          nil,
		"properties":    map[string]any{},
	}

	resource, err := parseARGRow(row, "sub-1")
	require.NoError(t, err)
	assert.Nil(t, resource.Tags)
}

func TestParseARGRow_MissingFields(t *testing.T) {
	row := map[string]any{
		"id":   "/subscriptions/sub-1/providers/Microsoft.Network/networkInterfaces/nic1",
		"type": "microsoft.network/networkinterfaces",
	}

	resource, err := parseARGRow(row, "sub-1")
	require.NoError(t, err)
	assert.Equal(t, "", resource.DisplayName)
	assert.Equal(t, "", resource.Location)
	assert.Equal(t, "", resource.ResourceGroup)
	assert.Nil(t, resource.Tags)
	assert.Nil(t, resource.Properties)
}

func TestParseARGRow_InvalidType(t *testing.T) {
	_, err := parseARGRow("not a map", "sub-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected row type")
}

func TestStringFromMap_Present(t *testing.T) {
	m := map[string]any{"key": "value"}
	assert.Equal(t, "value", stringFromMap(m, "key"))
}

func TestStringFromMap_Missing(t *testing.T) {
	m := map[string]any{"other": "value"}
	assert.Equal(t, "", stringFromMap(m, "key"))
}

func TestStringFromMap_NonString(t *testing.T) {
	m := map[string]any{"key": 42}
	assert.Equal(t, "", stringFromMap(m, "key"))
}

func TestStringFromMap_NilValue(t *testing.T) {
	m := map[string]any{"key": nil}
	assert.Equal(t, "", stringFromMap(m, "key"))
}
