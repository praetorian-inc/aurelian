package recon

import (
	"fmt"
	"testing"

	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockResolver struct {
	subs []azuretypes.SubscriptionInfo
	err  error
}

func (m *mockResolver) Resolve(id string, out *pipeline.P[azuretypes.SubscriptionInfo]) error {
	for _, s := range m.subs {
		if s.ID == id {
			out.Send(s)
			return nil
		}
	}
	return fmt.Errorf("subscription %s not found", id)
}

func (m *mockResolver) ListAllSubscriptions() ([]azuretypes.SubscriptionInfo, error) {
	return m.subs, m.err
}

func TestResolveSubscriptionIDs_SpecificIDs(t *testing.T) {
	resolver := &mockResolver{}
	ids, err := resolveSubscriptionIDs([]string{"sub-1", "sub-2"}, resolver)
	require.NoError(t, err)
	assert.Equal(t, []string{"sub-1", "sub-2"}, ids)
}

func TestResolveSubscriptionIDs_All(t *testing.T) {
	resolver := &mockResolver{
		subs: []azuretypes.SubscriptionInfo{
			{ID: "sub-1", DisplayName: "Sub 1"},
			{ID: "sub-2", DisplayName: "Sub 2"},
		},
	}
	ids, err := resolveSubscriptionIDs([]string{"all"}, resolver)
	require.NoError(t, err)
	assert.Equal(t, []string{"sub-1", "sub-2"}, ids)
}

func TestResolveSubscriptionIDs_AllCaseInsensitive(t *testing.T) {
	resolver := &mockResolver{
		subs: []azuretypes.SubscriptionInfo{{ID: "sub-1"}},
	}
	ids, err := resolveSubscriptionIDs([]string{"ALL"}, resolver)
	require.NoError(t, err)
	assert.Equal(t, []string{"sub-1"}, ids)
}

func TestResolveSubscriptionIDs_AllError(t *testing.T) {
	resolver := &mockResolver{err: fmt.Errorf("auth failed")}
	_, err := resolveSubscriptionIDs([]string{"all"}, resolver)
	assert.Error(t, err)
}

func TestAzureResourceFromID_Standard(t *testing.T) {
	id := "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/my-vm"
	r, err := azureResourceFromID(id)
	require.NoError(t, err)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", r.SubscriptionID)
	assert.Equal(t, "rg-test", r.ResourceGroup)
	assert.Equal(t, "Microsoft.Compute/virtualMachines", r.ResourceType)
	assert.Equal(t, id, r.ResourceID)
}

func TestAzureResourceFromID_WebApp(t *testing.T) {
	id := "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/my-rg/providers/Microsoft.Web/sites/my-app"
	r, err := azureResourceFromID(id)
	require.NoError(t, err)
	assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.SubscriptionID)
	assert.Equal(t, "my-rg", r.ResourceGroup)
	assert.Equal(t, "Microsoft.Web/sites", r.ResourceType)
	assert.Equal(t, id, r.ResourceID)
}

func TestAzureResourceFromID_InvalidSubscriptionID(t *testing.T) {
	id := "/subscriptions/not-a-uuid/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/my-vm"
	_, err := azureResourceFromID(id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid subscription ID")
}

func TestAzureResourceFromID_Invalid(t *testing.T) {
	_, err := azureResourceFromID("")
	assert.Error(t, err)

	_, err = azureResourceFromID("/subscriptions/sub-123")
	assert.Error(t, err)
}

func TestAzureResourceFromID_MissingMetadata(t *testing.T) {
	// azureResourceFromID only parses the ID string — Location, DisplayName,
	// TenantID are NOT populated. These require hydration via ARG.
	id := "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/my-vm"
	r, err := azureResourceFromID(id)
	require.NoError(t, err)
	assert.Empty(t, r.Location, "Location should be empty before hydration")
	assert.Empty(t, r.DisplayName, "DisplayName should be empty before hydration")
	assert.Empty(t, r.TenantID, "TenantID should be empty before hydration")
}

// TestAzureResourceFromID_SubscriptionScopedResources documents a known limitation:
// subscription-scoped resource IDs (no resourceGroups segment) are rejected by
// azureResourceFromID because ParseAzureResourceID and ResourceTypeFromID both
// require 8+ path segments with resourceGroups at index 2.
//
// Affected resource types: policy definitions, blueprints, subscription-scope deployments.
// These resources work in the normal subscription-wide enumeration path (the ARM
// enumerator emits them and extractors handle them individually), but cannot be
// targeted directly via --resource-id.
//
// TODO: support subscription-scoped IDs in azureResourceFromID to enable
// --resource-id targeting for policy definitions, blueprints, and
// subscription-scope deployments.
func TestAzureResourceFromID_SubscriptionScopedResources(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{
			name: "policy definition",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Authorization/policyDefinitions/my-custom-policy",
		},
		{
			name: "blueprint",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Blueprint/blueprints/my-blueprint",
		},
		{
			name: "subscription-scope deployment",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Resources/deployments/my-deployment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := azureResourceFromID(tt.id)
			assert.Error(t, err, "subscription-scoped %s IDs are not yet supported by --resource-id", tt.name)
			assert.Contains(t, err.Error(), "too few segments")
		})
	}
}

func TestHydrateFromARG_NilCred(t *testing.T) {
	resources := []output.AzureResource{
		{SubscriptionID: "sub-1", ResourceID: "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"},
	}
	// Should not panic with nil credential.
	hydrateFromARG(nil, resources)
	assert.Empty(t, resources[0].Location, "should remain empty with nil cred")
}

func TestHydrateFromARG_EmptyResources(t *testing.T) {
	// Should not panic with empty slice.
	hydrateFromARG(nil, nil)
	hydrateFromARG(nil, []output.AzureResource{})
}

func TestStrVal(t *testing.T) {
	m := map[string]any{
		"location": "eastus",
		"name":     "my-vm",
		"count":    42,
		"nil":      nil,
	}
	assert.Equal(t, "eastus", strVal(m, "location"))
	assert.Equal(t, "my-vm", strVal(m, "name"))
	assert.Equal(t, "", strVal(m, "count"))     // int → empty string
	assert.Equal(t, "", strVal(m, "nil"))        // nil → empty string
	assert.Equal(t, "", strVal(m, "missing"))    // missing key → empty string
}
