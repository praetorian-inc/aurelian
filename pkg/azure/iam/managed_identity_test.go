package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// resourceGraphObjectResponse builds a Resource Graph response in object format.
func resourceGraphObjectResponse(rows []map[string]any) map[string]any {
	return map[string]any{"data": rows}
}

// resourceGraphTabularResponse builds a Resource Graph response in tabular format.
func resourceGraphTabularResponse(rows [][]any) map[string]any {
	return map[string]any{
		"data": map[string]any{
			"columns": []map[string]string{
				{"name": "id"},
				{"name": "name"},
				{"name": "type"},
				{"name": "subscriptionId"},
				{"name": "identity"},
			},
			"rows": rows,
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestManagedIdentityCollect_UserAssigned(t *testing.T) {
	mock := newMockARMClient()

	subID := "sub-1"
	miPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31", subID)

	mock.onGet(miPath, armListBody([]map[string]any{
		{
			"id":       "/subscriptions/sub-1/resourceGroups/rg-test/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1",
			"name":     "mi-1",
			"location": "eastus",
			"properties": map[string]any{
				"principalId": "pid-1",
				"clientId":    "cid-1",
				"tenantId":    "tid-1",
			},
		},
		{
			"id":       "/subscriptions/sub-1/resourceGroups/rg-other/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-2",
			"name":     "mi-2",
			"location": "westus",
			"properties": map[string]any{
				"principalId": "pid-2",
				"clientId":    "cid-2",
				"tenantId":    "tid-1",
			},
		},
	}, ""))

	// Empty Resource Graph response
	mock.onGet("/providers/Microsoft.ResourceGraph/resources", resourceGraphObjectResponse(nil))

	collector := newManagedIdentityCollectorWithClient(mock)
	data, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err)

	require.Len(t, data.Identities, 2)

	mi1 := data.Identities[0]
	assert.Equal(t, "/subscriptions/sub-1/resourcegroups/rg-test/providers/microsoft.managedidentity/userassignedidentities/mi-1", mi1.ID, "ID should be lowercased")
	assert.Equal(t, "mi-1", mi1.Name)
	assert.Equal(t, "eastus", mi1.Location)
	assert.Equal(t, "pid-1", mi1.PrincipalID)
	assert.Equal(t, "cid-1", mi1.ClientID)
	assert.Equal(t, "tid-1", mi1.TenantID)
	assert.Equal(t, "sub-1", mi1.SubscriptionID)
	assert.Equal(t, "rg-test", mi1.ResourceGroup)

	mi2 := data.Identities[1]
	assert.Equal(t, "rg-other", mi2.ResourceGroup)
}

func TestManagedIdentityCollect_ResourceGroupExtraction(t *testing.T) {
	mock := newMockARMClient()

	subID := "sub-1"
	miPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31", subID)

	tests := []struct {
		name            string
		id              string
		expectedRG      string
	}{
		{"standard path", "/subscriptions/sub-1/resourceGroups/MyRG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi", "MyRG"},
		{"short path", "/a/b/c", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock.onGet(miPath, armListBody([]map[string]any{
				{
					"id": tc.id, "name": "test-mi", "location": "eastus",
					"properties": map[string]any{"principalId": "p", "clientId": "c", "tenantId": "t"},
				},
			}, ""))
			mock.onGet("/providers/Microsoft.ResourceGraph/resources", resourceGraphObjectResponse(nil))

			collector := newManagedIdentityCollectorWithClient(mock)
			data, err := collector.Collect(context.Background(), []string{subID})
			require.NoError(t, err)
			require.Len(t, data.Identities, 1)
			assert.Equal(t, tc.expectedRG, data.Identities[0].ResourceGroup)
		})
	}
}

func TestManagedIdentityCollect_ResourceGraph_ObjectFormat(t *testing.T) {
	mock := newMockARMClient()

	subID := "sub-1"
	miPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31", subID)
	mock.onGet(miPath, armListBody([]any{}, ""))

	// Resource Graph returns data as array of objects
	graphResp := resourceGraphObjectResponse([]map[string]any{
		{
			"id":             "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
			"name":           "vm-1",
			"type":           "microsoft.compute/virtualmachines",
			"subscriptionId": "sub-1",
			"identity": map[string]any{
				"type":        "SystemAssigned, UserAssigned",
				"principalId": "sys-pid-1",
				"userAssignedIdentities": map[string]any{
					"/Subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1": map[string]any{
						"principalId": "ua-pid-1",
						"clientId":    "ua-cid-1",
					},
				},
			},
		},
	})
	graphData, _ := json.Marshal(graphResp)
	mock.mu.Lock()
	mock.responses["/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"] = graphData
	mock.mu.Unlock()

	collector := newManagedIdentityCollectorWithClient(mock)
	data, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err)

	require.Len(t, data.Attachments, 1)
	att := data.Attachments[0]
	assert.Equal(t, "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1", att.ResourceID)
	assert.Equal(t, "vm-1", att.ResourceName)
	assert.Equal(t, "microsoft.compute/virtualmachines", att.ResourceType)
	assert.Equal(t, "sub-1", att.SubscriptionID)
	assert.Equal(t, "SystemAssigned, UserAssigned", att.IdentityType)
	assert.Equal(t, "sys-pid-1", att.PrincipalID)
	require.Len(t, att.UserAssignedIDs, 1)
	assert.Contains(t, att.UserAssignedIDs[0], "microsoft.managedidentity", "user-assigned IDs should be lowercased")
}

func TestManagedIdentityCollect_ResourceGraph_TabularFormat(t *testing.T) {
	mock := newMockARMClient()

	subID := "sub-1"
	miPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31", subID)
	mock.onGet(miPath, armListBody([]any{}, ""))

	// Resource Graph returns data in tabular format
	graphResp := resourceGraphTabularResponse([][]any{
		{
			"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-tab",
			"vm-tab",
			"microsoft.compute/virtualmachines",
			"sub-1",
			map[string]any{
				"type":        "SystemAssigned",
				"principalId": "sys-pid-tab",
			},
		},
	})
	graphData, _ := json.Marshal(graphResp)
	mock.mu.Lock()
	mock.responses["/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"] = graphData
	mock.mu.Unlock()

	collector := newManagedIdentityCollectorWithClient(mock)
	data, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err)

	require.Len(t, data.Attachments, 1)
	att := data.Attachments[0]
	assert.Equal(t, "vm-tab", att.ResourceName)
	assert.Equal(t, "SystemAssigned", att.IdentityType)
	assert.Equal(t, "sys-pid-tab", att.PrincipalID)
}

func TestManagedIdentityCollect_MultipleSubscriptions(t *testing.T) {
	mock := newMockARMClient()

	for _, subID := range []string{"sub-a", "sub-b"} {
		miPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31", subID)
		mock.onGet(miPath, armListBody([]map[string]any{
			{
				"id": fmt.Sprintf("/subscriptions/%s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-%s", subID, subID),
				"name": "mi-" + subID, "location": "eastus",
				"properties": map[string]any{"principalId": "p-" + subID, "clientId": "c-" + subID, "tenantId": "t"},
			},
		}, ""))
	}
	mock.onGet("/providers/Microsoft.ResourceGraph/resources", resourceGraphObjectResponse(nil))

	collector := newManagedIdentityCollectorWithClient(mock)
	data, err := collector.Collect(context.Background(), []string{"sub-a", "sub-b"})
	require.NoError(t, err)

	assert.Len(t, data.Identities, 2)
	assert.Equal(t, "sub-a", data.Identities[0].SubscriptionID)
	assert.Equal(t, "sub-b", data.Identities[1].SubscriptionID)
}

func TestManagedIdentityCollect_SubscriptionFailure_ContinuesOthers(t *testing.T) {
	mock := newMockARMClient()

	badPath := "/subscriptions/sub-bad/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31"
	mock.onGetError(badPath, fmt.Errorf("access denied"))

	goodPath := "/subscriptions/sub-good/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31"
	mock.onGet(goodPath, armListBody([]map[string]any{
		{
			"id": "/subscriptions/sub-good/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi",
			"name": "mi", "location": "eastus",
			"properties": map[string]any{"principalId": "p", "clientId": "c", "tenantId": "t"},
		},
	}, ""))
	mock.onGet("/providers/Microsoft.ResourceGraph/resources", resourceGraphObjectResponse(nil))

	collector := newManagedIdentityCollectorWithClient(mock)
	data, err := collector.Collect(context.Background(), []string{"sub-bad", "sub-good"})
	require.NoError(t, err, "should not fail when one subscription errors")

	assert.Len(t, data.Identities, 1, "only sub-good MI should be collected")
	assert.Equal(t, "sub-good", data.Identities[0].SubscriptionID)
}

func TestManagedIdentityCollect_EmptySubscriptions(t *testing.T) {
	mock := newMockARMClient()

	collector := newManagedIdentityCollectorWithClient(mock)
	data, err := collector.Collect(context.Background(), []string{})
	require.NoError(t, err)
	assert.Empty(t, data.Identities)
	assert.Empty(t, data.Attachments)
}

func TestManagedIdentityCollect_Pagination(t *testing.T) {
	mock := newMockARMClient()

	subID := "sub-paged"
	page1Path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31", subID)
	page2Path := "https://management.azure.com/subscriptions/sub-paged/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31&$skipToken=page2"

	mock.onGet(page1Path, armListBody([]map[string]any{
		{
			"id": "/subscriptions/sub-paged/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1",
			"name": "mi-1", "location": "eastus",
			"properties": map[string]any{"principalId": "p-1", "clientId": "c-1", "tenantId": "t"},
		},
	}, page2Path))

	mock.onGet(page2Path, armListBody([]map[string]any{
		{
			"id": "/subscriptions/sub-paged/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-2",
			"name": "mi-2", "location": "eastus",
			"properties": map[string]any{"principalId": "p-2", "clientId": "c-2", "tenantId": "t"},
		},
	}, ""))

	mock.onGet("/providers/Microsoft.ResourceGraph/resources", resourceGraphObjectResponse(nil))

	collector := newManagedIdentityCollectorWithClient(mock)
	data, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err)

	assert.Len(t, data.Identities, 2, "both pages should be collected")
	assert.Equal(t, "p-1", data.Identities[0].PrincipalID)
	assert.Equal(t, "p-2", data.Identities[1].PrincipalID)
}

func TestManagedIdentityCollect_ResourceGraphFailure_StillReturnsIdentities(t *testing.T) {
	mock := newMockARMClient()

	subID := "sub-1"
	miPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31", subID)
	mock.onGet(miPath, armListBody([]map[string]any{
		{
			"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi",
			"name": "mi", "location": "eastus",
			"properties": map[string]any{"principalId": "p", "clientId": "c", "tenantId": "t"},
		},
	}, ""))

	// Resource Graph fails
	mock.onGetError("/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01", fmt.Errorf("forbidden"))

	collector := newManagedIdentityCollectorWithClient(mock)
	data, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err, "should not fail when Resource Graph errors")

	assert.Len(t, data.Identities, 1, "identities still collected")
	assert.Empty(t, data.Attachments, "attachments empty when Resource Graph fails")
}
