package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAzureResourceID_VM(t *testing.T) {
	id := "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm"
	sub, rg, segments, err := parseAzureResourceID(id)
	require.NoError(t, err)
	assert.Equal(t, "sub-123", sub)
	assert.Equal(t, "my-rg", rg)
	assert.Equal(t, "my-vm", segments["virtualMachines"])
}

func TestParseAzureResourceID_WebApp(t *testing.T) {
	id := "/subscriptions/sub-456/resourceGroups/web-rg/providers/Microsoft.Web/sites/my-app"
	sub, rg, segments, err := parseAzureResourceID(id)
	require.NoError(t, err)
	assert.Equal(t, "sub-456", sub)
	assert.Equal(t, "web-rg", rg)
	assert.Equal(t, "my-app", segments["sites"])
}

func TestParseAzureResourceID_AutomationAccount(t *testing.T) {
	id := "/subscriptions/sub-789/resourceGroups/auto-rg/providers/Microsoft.Automation/automationAccounts/my-account"
	sub, rg, segments, err := parseAzureResourceID(id)
	require.NoError(t, err)
	assert.Equal(t, "sub-789", sub)
	assert.Equal(t, "auto-rg", rg)
	assert.Equal(t, "my-account", segments["automationAccounts"])
}

func TestParseAzureResourceID_StorageAccount(t *testing.T) {
	id := "/subscriptions/sub-abc/resourceGroups/storage-rg/providers/Microsoft.Storage/storageAccounts/mystorage"
	sub, rg, segments, err := parseAzureResourceID(id)
	require.NoError(t, err)
	assert.Equal(t, "sub-abc", sub)
	assert.Equal(t, "storage-rg", rg)
	assert.Equal(t, "mystorage", segments["storageAccounts"])
}

func TestParseAzureResourceID_Empty(t *testing.T) {
	_, _, _, err := parseAzureResourceID("")
	assert.Error(t, err)
}

func TestParseAzureResourceID_Invalid(t *testing.T) {
	_, _, _, err := parseAzureResourceID("/subscriptions/sub-123")
	assert.Error(t, err)
}
