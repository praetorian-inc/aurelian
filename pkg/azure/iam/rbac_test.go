package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock ARMClient
// ---------------------------------------------------------------------------

type mockARMClient struct {
	mu        sync.Mutex
	responses map[string][]byte
	errors    map[string]error
	calls     map[string]int
}

func newMockARMClient() *mockARMClient {
	return &mockARMClient{
		responses: make(map[string][]byte),
		errors:    make(map[string]error),
		calls:     make(map[string]int),
	}
}

func (m *mockARMClient) onGet(path string, body any) {
	data, _ := json.Marshal(body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[path] = data
}

func (m *mockARMClient) onGetError(path string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[path] = err
}

func (m *mockARMClient) Get(_ context.Context, path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[path]++

	if err, ok := m.errors[path]; ok {
		return nil, err
	}
	if data, ok := m.responses[path]; ok {
		return data, nil
	}
	for k, v := range m.responses {
		if strings.HasSuffix(path, k) || strings.Contains(path, k) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("no mock response for path: %s", path)
}

func (m *mockARMClient) Post(_ context.Context, path string, _ []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["POST:"+path]++

	if err, ok := m.errors[path]; ok {
		return nil, err
	}
	if data, ok := m.responses[path]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("no mock response for POST path: %s", path)
}

func (m *mockARMClient) callCount(path string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[path]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// armListBody builds an ARM list response envelope.
func armListBody(items any, nextLink string) map[string]any {
	body := map[string]any{"value": items}
	if nextLink != "" {
		body["nextLink"] = nextLink
	}
	return body
}

// makeARMRoleAssignment builds an ARM-shaped role assignment.
func makeARMRoleAssignment(id, principalID, roleDefID, scope, principalType string) map[string]any {
	return map[string]any{
		"id":   id,
		"name": id,
		"properties": map[string]any{
			"roleDefinitionId": roleDefID,
			"principalId":      principalID,
			"principalType":    principalType,
			"scope":            scope,
		},
	}
}

// makeARMRoleDefinition builds an ARM-shaped role definition.
func makeARMRoleDefinition(id, roleName, description, roleType string, actions []string) map[string]any {
	return map[string]any{
		"id":   id,
		"name": id,
		"properties": map[string]any{
			"roleName":    roleName,
			"description": description,
			"type":        roleType,
			"permissions": []map[string]any{
				{"actions": actions, "notActions": []string{}},
			},
			"assignableScopes": []string{"/"},
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRBACCollect_SingleSubscription(t *testing.T) {
	mock := newMockARMClient()

	subID := "sub-1"
	assignPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", subID)
	defPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", subID)

	roleDefID := "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/def-1"

	mock.onGet(assignPath, armListBody([]any{
		makeARMRoleAssignment("/subscriptions/sub-1/roleAssignments/a-1", "p-1", roleDefID, "/subscriptions/sub-1", "User"),
		makeARMRoleAssignment("/subscriptions/sub-1/roleAssignments/a-2", "p-2", roleDefID, "/subscriptions/sub-1", "Group"),
	}, ""))

	mock.onGet(defPath, armListBody([]any{
		makeARMRoleDefinition(roleDefID, "Contributor", "Can manage resources", "BuiltInRole", []string{"*"}),
	}, ""))

	collector := newRBACCollectorWithClient(mock)
	results, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err)
	require.Len(t, results, 1)

	data := results[0]
	assert.Equal(t, subID, data.SubscriptionID)
	assert.Len(t, data.Assignments, 2)
	assert.Equal(t, "p-1", data.Assignments[0].PrincipalID)
	assert.Equal(t, "User", data.Assignments[0].PrincipalType)
	assert.Equal(t, roleDefID, data.Assignments[0].RoleDefinitionID)
	assert.Equal(t, "p-2", data.Assignments[1].PrincipalID)

	def, ok := data.Definitions.Get(roleDefID)
	require.True(t, ok)
	assert.Equal(t, "Contributor", def.RoleName)
	assert.Equal(t, "BuiltInRole", def.RoleType)
	require.Len(t, def.Permissions, 1)
	assert.Equal(t, []string{"*"}, def.Permissions[0].Actions)
}

func TestRBACCollect_MultipleSubscriptions(t *testing.T) {
	mock := newMockARMClient()

	for _, subID := range []string{"sub-a", "sub-b"} {
		assignPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", subID)
		defPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", subID)

		mock.onGet(assignPath, armListBody([]any{
			makeARMRoleAssignment(fmt.Sprintf("/%s/a-1", subID), "p-1", "def-1", "/subscriptions/"+subID, "User"),
		}, ""))
		mock.onGet(defPath, armListBody([]any{}, ""))
	}

	collector := newRBACCollectorWithClient(mock)
	results, err := collector.Collect(context.Background(), []string{"sub-a", "sub-b"})
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "sub-a", results[0].SubscriptionID)
	assert.Equal(t, "sub-b", results[1].SubscriptionID)
	assert.Len(t, results[0].Assignments, 1)
	assert.Len(t, results[1].Assignments, 1)
}

func TestRBACCollect_SubscriptionFailure(t *testing.T) {
	mock := newMockARMClient()

	// sub-good succeeds
	goodAssign := "/subscriptions/sub-good/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
	goodDef := "/subscriptions/sub-good/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
	mock.onGet(goodAssign, armListBody([]any{
		makeARMRoleAssignment("a-1", "p-1", "def-1", "/subscriptions/sub-good", "User"),
	}, ""))
	mock.onGet(goodDef, armListBody([]any{}, ""))

	// sub-bad fails on role assignments
	badAssign := "/subscriptions/sub-bad/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
	mock.onGetError(badAssign, fmt.Errorf("access denied"))

	collector := newRBACCollectorWithClient(mock)
	results, err := collector.Collect(context.Background(), []string{"sub-bad", "sub-good"})
	require.NoError(t, err)
	require.Len(t, results, 1, "only sub-good should succeed")
	assert.Equal(t, "sub-good", results[0].SubscriptionID)
}

func TestRBACCollect_EmptySubscription(t *testing.T) {
	mock := newMockARMClient()

	subID := "sub-empty"
	assignPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", subID)
	defPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", subID)

	mock.onGet(assignPath, armListBody([]any{}, ""))
	mock.onGet(defPath, armListBody([]any{}, ""))

	collector := newRBACCollectorWithClient(mock)
	results, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, subID, results[0].SubscriptionID)
	assert.Empty(t, results[0].Assignments)
}

func TestRBACCollect_Pagination(t *testing.T) {
	mock := newMockARMClient()

	subID := "sub-paged"
	page1Path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", subID)
	page2Path := "https://management.azure.com/subscriptions/sub-paged/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$skipToken=page2"
	defPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", subID)

	mock.onGet(page1Path, armListBody([]any{
		makeARMRoleAssignment("a-1", "p-1", "def-1", "/subscriptions/sub-paged", "User"),
	}, page2Path))

	mock.onGet(page2Path, armListBody([]any{
		makeARMRoleAssignment("a-2", "p-2", "def-1", "/subscriptions/sub-paged", "Group"),
	}, ""))

	mock.onGet(defPath, armListBody([]any{}, ""))

	collector := newRBACCollectorWithClient(mock)
	results, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Len(t, results[0].Assignments, 2, "both pages should be collected")
	assert.Equal(t, "p-1", results[0].Assignments[0].PrincipalID)
	assert.Equal(t, "p-2", results[0].Assignments[1].PrincipalID)
}

func TestRBACCollect_DefinitionFailure_StillReturnsAssignments(t *testing.T) {
	mock := newMockARMClient()

	subID := "sub-def-fail"
	assignPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", subID)
	defPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", subID)

	roleDefID := "/subscriptions/sub-def-fail/providers/Microsoft.Authorization/roleDefinitions/def-1"

	// Assignments succeed
	mock.onGet(assignPath, armListBody([]any{
		makeARMRoleAssignment("/subscriptions/sub-def-fail/roleAssignments/a-1", "p-1", roleDefID, "/subscriptions/sub-def-fail", "User"),
		makeARMRoleAssignment("/subscriptions/sub-def-fail/roleAssignments/a-2", "p-2", roleDefID, "/subscriptions/sub-def-fail", "Group"),
	}, ""))

	// Definitions fail
	mock.onGetError(defPath, fmt.Errorf("role definitions unavailable"))

	collector := newRBACCollectorWithClient(mock)
	results, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err)
	require.Len(t, results, 1, "subscription should still be returned despite definition failure")

	data := results[0]
	assert.Equal(t, subID, data.SubscriptionID)
	assert.Len(t, data.Assignments, 2, "assignments should be present")
	assert.Equal(t, "p-1", data.Assignments[0].PrincipalID)
	assert.Equal(t, "p-2", data.Assignments[1].PrincipalID)
	assert.Equal(t, roleDefID, data.Assignments[0].RoleDefinitionID)

	// Definitions map should be initialized but empty
	assert.Equal(t, 0, data.Definitions.Len(), "definitions map should be empty when fetch fails")
}

func TestPaginateARM_SinglePage(t *testing.T) {
	mock := newMockARMClient()

	type simpleItem struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	mock.onGet("/test/items", armListBody([]simpleItem{
		{ID: "1", Name: "alpha"},
		{ID: "2", Name: "beta"},
	}, ""))

	items, err := paginateARM[simpleItem](context.Background(), mock, "/test/items")
	require.NoError(t, err)
	require.Len(t, items, 2)
	assert.Equal(t, "alpha", items[0].Name)
	assert.Equal(t, "beta", items[1].Name)
}
