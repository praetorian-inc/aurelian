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
	id := "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/my-vm"
	r, err := azureResourceFromID(id)
	require.NoError(t, err)
	assert.Equal(t, "sub-123", r.SubscriptionID)
	assert.Equal(t, "rg-test", r.ResourceGroup)
	assert.Equal(t, "Microsoft.Compute/virtualMachines", r.ResourceType)
	assert.Equal(t, id, r.ResourceID)
}

func TestAzureResourceFromID_WebApp(t *testing.T) {
	id := "/subscriptions/abc/resourceGroups/my-rg/providers/Microsoft.Web/sites/my-app"
	r, err := azureResourceFromID(id)
	require.NoError(t, err)
	assert.Equal(t, "abc", r.SubscriptionID)
	assert.Equal(t, "my-rg", r.ResourceGroup)
	assert.Equal(t, "Microsoft.Web/sites", r.ResourceType)
	assert.Equal(t, id, r.ResourceID)
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
	id := "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/my-vm"
	r, err := azureResourceFromID(id)
	require.NoError(t, err)
	assert.Empty(t, r.Location, "Location should be empty before hydration")
	assert.Empty(t, r.DisplayName, "DisplayName should be empty before hydration")
	assert.Empty(t, r.TenantID, "TenantID should be empty before hydration")
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
