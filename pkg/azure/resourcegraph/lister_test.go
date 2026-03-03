package resourcegraph

import (
	"testing"

	azurehelpers "github.com/praetorian-inc/aurelian/internal/helpers/azure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSub = azurehelpers.SubscriptionInfo{
	ID:          "sub-1",
	DisplayName: "Test Subscription",
	TenantID:    "tenant-1",
}

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

	resource, err := parseARGRow(row, testSub)
	require.NoError(t, err)
	assert.Equal(t, "sub-1", resource.SubscriptionID)
	assert.Equal(t, "Test Subscription", resource.SubscriptionName)
	assert.Equal(t, "tenant-1", resource.TenantID)
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

	resource, err := parseARGRow(row, testSub)
	require.NoError(t, err)
	assert.Nil(t, resource.Tags)
}

func TestParseARGRow_MissingFields(t *testing.T) {
	row := map[string]any{
		"id":   "/subscriptions/sub-1/providers/Microsoft.Network/networkInterfaces/nic1",
		"type": "microsoft.network/networkinterfaces",
	}

	resource, err := parseARGRow(row, testSub)
	require.NoError(t, err)
	assert.Equal(t, "", resource.DisplayName)
	assert.Equal(t, "", resource.Location)
	assert.Equal(t, "", resource.ResourceGroup)
	assert.Nil(t, resource.Tags)
	assert.Nil(t, resource.Properties)
	assert.Equal(t, "Test Subscription", resource.SubscriptionName)
	assert.Equal(t, "tenant-1", resource.TenantID)
}

func TestParseARGRow_InvalidType(t *testing.T) {
	_, err := parseARGRow("not a map", testSub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected row type")
}

func TestParseARGRow_CustomProjectedFields(t *testing.T) {
	row := map[string]any{
		"id":                  "/subscriptions/sub-1/providers/Microsoft.Web/sites/app1",
		"name":                "app1",
		"type":                "microsoft.web/sites",
		"location":            "eastus",
		"resourceGroup":       "rg",
		"publicNetworkAccess": "Enabled",
		"openPorts":           []any{"80", "443"},
	}

	resource, err := parseARGRow(row, testSub)
	require.NoError(t, err)
	assert.Equal(t, "Enabled", resource.Properties["publicNetworkAccess"])
	assert.Equal(t, []any{"80", "443"}, resource.Properties["openPorts"])
}

func TestParseARGRow_CustomFieldsMergedWithProperties(t *testing.T) {
	row := map[string]any{
		"id":                 "/subscriptions/sub-1/providers/Microsoft.Storage/storageAccounts/sa1",
		"name":               "sa1",
		"type":               "microsoft.storage/storageaccounts",
		"location":           "westus2",
		"resourceGroup":      "rg",
		"properties":         map[string]any{"supportsHttpsTrafficOnly": true},
		"virtualNetworkType": "Internal",
	}

	resource, err := parseARGRow(row, testSub)
	require.NoError(t, err)
	assert.Equal(t, true, resource.Properties["supportsHttpsTrafficOnly"])
	assert.Equal(t, "Internal", resource.Properties["virtualNetworkType"])
}

func TestTryUnmarshalJSONStrings(t *testing.T) {
	m := map[string]any{
		"plain":       "hello",
		"number":      42,
		"jsonObject":  `{"key":"value","nested":{"a":1}}`,
		"jsonArray":   `[1,2,3]`,
		"shortStr":    "x",
		"invalidJSON": `{not json}`,
	}

	tryUnmarshalJSONStrings(m)

	assert.Equal(t, "hello", m["plain"])
	assert.Equal(t, 42, m["number"])
	assert.Equal(t, map[string]any{"key": "value", "nested": map[string]any{"a": float64(1)}}, m["jsonObject"])
	assert.Equal(t, []any{float64(1), float64(2), float64(3)}, m["jsonArray"])
	assert.Equal(t, "x", m["shortStr"])
	assert.Equal(t, `{not json}`, m["invalidJSON"])
}

func TestParseARGRow_JSONStringInProperties(t *testing.T) {
	row := map[string]any{
		"id":   "/subscriptions/sub-1/providers/Microsoft.Network/networkInterfaces/nic1",
		"type": "microsoft.network/networkinterfaces",
		"properties": map[string]any{
			"ipConfigurations": `[{"name":"ipconfig1","properties":{"privateIPAddress":"10.0.0.4"}}]`,
			"normalProp":       "just a string",
		},
	}

	resource, err := parseARGRow(row, testSub)
	require.NoError(t, err)
	assert.Equal(t, "just a string", resource.Properties["normalProp"])

	parsed, ok := resource.Properties["ipConfigurations"].([]any)
	require.True(t, ok, "ipConfigurations should be unmarshaled from JSON string")
	require.Len(t, parsed, 1)
	first, ok := parsed[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ipconfig1", first["name"])
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
