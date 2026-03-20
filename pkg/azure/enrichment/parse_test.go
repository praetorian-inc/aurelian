package enrichment

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseResource_Standard(t *testing.T) {
	result := templates.ARGQueryResult{
		ResourceID:     "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm",
		SubscriptionID: "sub-123",
		ResourceName:   "my-vm",
	}
	sub, rg, name, err := ParseResource(result)
	require.NoError(t, err)
	assert.Equal(t, "sub-123", sub)
	assert.Equal(t, "my-rg", rg)
	assert.Equal(t, "my-vm", name)
}

func TestParseResource_CaseInsensitiveResourceGroups(t *testing.T) {
	result := templates.ARGQueryResult{
		ResourceID:     "/subscriptions/sub-1/RESOURCEGROUPS/My-RG/providers/Microsoft.Web/sites/app",
		SubscriptionID: "sub-1",
		ResourceName:   "app",
	}
	_, rg, _, err := ParseResource(result)
	require.NoError(t, err)
	assert.Equal(t, "My-RG", rg)
}

func TestParseResource_MissingSubscriptionID(t *testing.T) {
	result := templates.ARGQueryResult{
		ResourceID:     "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
		SubscriptionID: "",
		ResourceName:   "vm",
	}
	_, _, _, err := ParseResource(result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sub=\"\"")
}

func TestParseResource_MissingResourceGroup(t *testing.T) {
	result := templates.ARGQueryResult{
		ResourceID:     "/subscriptions/sub-1/providers/Microsoft.Compute/virtualMachines/vm",
		SubscriptionID: "sub-1",
		ResourceName:   "vm",
	}
	_, _, _, err := ParseResource(result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rg=\"\"")
}

func TestParseResource_MissingName(t *testing.T) {
	result := templates.ARGQueryResult{
		ResourceID:     "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
		SubscriptionID: "sub-1",
		ResourceName:   "",
	}
	_, _, _, err := ParseResource(result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name=\"\"")
}
