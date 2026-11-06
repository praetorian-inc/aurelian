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
// Test: Full Collect with populated PIM data
// ---------------------------------------------------------------------------

func TestPIMCollect_PopulatedTenant(t *testing.T) {
	mock := newMockGraphClient()

	mock.onGet(pimActivePath, graphListResponse{
		Value: []map[string]any{
			{
				"id":               "active-1",
				"principalId":      "user-1",
				"roleDefinitionId": "role-def-1",
				"directoryScopeId": "/",
				"startDateTime":    "2025-01-01T00:00:00Z",
				"endDateTime":      "2026-01-01T00:00:00Z",
			},
			{
				"id":               "active-2",
				"principalId":      "user-2",
				"roleDefinitionId": "role-def-2",
				"directoryScopeId": "/administrativeUnits/au-1",
				"startDateTime":    "2025-06-01T00:00:00Z",
			},
		},
	})

	mock.onGet(pimEligiblePath, graphListResponse{
		Value: []map[string]any{
			{
				"id":               "eligible-1",
				"principalId":      "user-3",
				"roleDefinitionId": "role-def-1",
				"directoryScopeId": "/",
				"startDateTime":    "2025-03-01T00:00:00Z",
				"endDateTime":      "2025-09-01T00:00:00Z",
			},
		},
	})

	collector := newPIMCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, data)

	// Verify active assignments
	require.Len(t, data.ActiveAssignments, 2)
	assert.Equal(t, "active-1", data.ActiveAssignments[0].ID)
	assert.Equal(t, "user-1", data.ActiveAssignments[0].PrincipalID)
	assert.Equal(t, "role-def-1", data.ActiveAssignments[0].RoleDefinitionID)
	assert.Equal(t, "/", data.ActiveAssignments[0].Scope)
	assert.Equal(t, "active", data.ActiveAssignments[0].AssignmentType)
	assert.Equal(t, "2025-01-01T00:00:00Z", data.ActiveAssignments[0].StartDateTime)
	assert.Equal(t, "2026-01-01T00:00:00Z", data.ActiveAssignments[0].EndDateTime)

	assert.Equal(t, "active-2", data.ActiveAssignments[1].ID)
	assert.Equal(t, "/administrativeUnits/au-1", data.ActiveAssignments[1].Scope)
	assert.Equal(t, "active", data.ActiveAssignments[1].AssignmentType)

	// Verify eligible assignments
	require.Len(t, data.EligibleAssignments, 1)
	assert.Equal(t, "eligible-1", data.EligibleAssignments[0].ID)
	assert.Equal(t, "user-3", data.EligibleAssignments[0].PrincipalID)
	assert.Equal(t, "eligible", data.EligibleAssignments[0].AssignmentType)
	assert.Equal(t, "2025-03-01T00:00:00Z", data.EligibleAssignments[0].StartDateTime)
	assert.Equal(t, "2025-09-01T00:00:00Z", data.EligibleAssignments[0].EndDateTime)
}

// ---------------------------------------------------------------------------
// Test: Empty tenant — no assignments
// ---------------------------------------------------------------------------

func TestPIMCollect_EmptyTenant(t *testing.T) {
	mock := newMockGraphClient()

	emptyResp := graphListResponse{Value: json.RawMessage("[]")}
	mock.onGet(pimActivePath, emptyResp)
	mock.onGet(pimEligiblePath, emptyResp)

	collector := newPIMCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, data)

	assert.Empty(t, data.ActiveAssignments)
	assert.Empty(t, data.EligibleAssignments)
}

// ---------------------------------------------------------------------------
// Test: Active endpoint fails gracefully — eligible still collected
// ---------------------------------------------------------------------------

func TestPIMCollect_ActiveFailsGracefully(t *testing.T) {
	mock := newMockGraphClient()

	mock.onGetError(pimActivePath, fmt.Errorf("403 Forbidden: requires Azure AD Premium P2"))

	mock.onGet(pimEligiblePath, graphListResponse{
		Value: []map[string]any{
			{
				"id":               "eligible-1",
				"principalId":      "user-1",
				"roleDefinitionId": "role-def-1",
				"directoryScopeId": "/",
			},
		},
	})

	collector := newPIMCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, data)

	assert.Empty(t, data.ActiveAssignments)
	require.Len(t, data.EligibleAssignments, 1)
	assert.Equal(t, "eligible-1", data.EligibleAssignments[0].ID)
	assert.Equal(t, "eligible", data.EligibleAssignments[0].AssignmentType)
}

// ---------------------------------------------------------------------------
// Test: Eligible endpoint fails gracefully — active still collected
// ---------------------------------------------------------------------------

func TestPIMCollect_EligibleFailsGracefully(t *testing.T) {
	mock := newMockGraphClient()

	mock.onGet(pimActivePath, graphListResponse{
		Value: []map[string]any{
			{
				"id":               "active-1",
				"principalId":      "user-1",
				"roleDefinitionId": "role-def-1",
				"directoryScopeId": "/",
			},
		},
	})

	mock.onGetError(pimEligiblePath, fmt.Errorf("500 Internal Server Error"))

	collector := newPIMCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, data)

	require.Len(t, data.ActiveAssignments, 1)
	assert.Equal(t, "active-1", data.ActiveAssignments[0].ID)
	assert.Equal(t, "active", data.ActiveAssignments[0].AssignmentType)
	assert.Empty(t, data.EligibleAssignments)
}

// ---------------------------------------------------------------------------
// Test: Both endpoints fail — returns empty PIMData (not error)
// ---------------------------------------------------------------------------

func TestPIMCollect_BothFail(t *testing.T) {
	mock := newMockGraphClient()

	mock.onGetError(pimActivePath, fmt.Errorf("403 Forbidden"))
	mock.onGetError(pimEligiblePath, fmt.Errorf("403 Forbidden"))

	collector := newPIMCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, data)

	assert.Empty(t, data.ActiveAssignments)
	assert.Empty(t, data.EligibleAssignments)
}

// ---------------------------------------------------------------------------
// Test: Pagination — multi-page response for active assignments
// ---------------------------------------------------------------------------

func TestPIMCollect_Pagination(t *testing.T) {
	mock := newMockGraphClient()

	// First page of active assignments with nextLink
	page1, _ := json.Marshal(graphListResponse{
		Value: []map[string]any{
			{
				"id":               "active-1",
				"principalId":      "user-1",
				"roleDefinitionId": "role-def-1",
				"directoryScopeId": "/",
			},
		},
		NextLink: "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$skiptoken=page2",
	})
	mock.responses[pimActivePath] = page1

	// Second page (no nextLink — end of pagination)
	page2, _ := json.Marshal(graphListResponse{
		Value: []map[string]any{
			{
				"id":               "active-2",
				"principalId":      "user-2",
				"roleDefinitionId": "role-def-2",
				"directoryScopeId": "/administrativeUnits/au-1",
				"startDateTime":    "2025-06-01T00:00:00Z",
			},
		},
	})
	mock.responses["https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$skiptoken=page2"] = page2

	// Eligible — empty
	mock.onGet(pimEligiblePath, graphListResponse{Value: json.RawMessage("[]")})

	collector := newPIMCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, data)

	// Should have both active assignments from both pages
	require.Len(t, data.ActiveAssignments, 2)
	assert.Equal(t, "active-1", data.ActiveAssignments[0].ID)
	assert.Equal(t, "user-1", data.ActiveAssignments[0].PrincipalID)
	assert.Equal(t, "active", data.ActiveAssignments[0].AssignmentType)

	assert.Equal(t, "active-2", data.ActiveAssignments[1].ID)
	assert.Equal(t, "user-2", data.ActiveAssignments[1].PrincipalID)
	assert.Equal(t, "/administrativeUnits/au-1", data.ActiveAssignments[1].Scope)
	assert.Equal(t, "2025-06-01T00:00:00Z", data.ActiveAssignments[1].StartDateTime)

	assert.Empty(t, data.EligibleAssignments)
}
