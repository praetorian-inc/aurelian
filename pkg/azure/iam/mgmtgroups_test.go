package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock MgmtGroupClient
// ---------------------------------------------------------------------------

type mockMgmtGroupClient struct {
	mu        sync.Mutex
	responses map[string][]byte
	errors    map[string]error
	calls     map[string]int
}

func newMockMgmtGroupClient() *mockMgmtGroupClient {
	return &mockMgmtGroupClient{
		responses: make(map[string][]byte),
		errors:    make(map[string]error),
		calls:     make(map[string]int),
	}
}

func (m *mockMgmtGroupClient) onGet(url string, body any) {
	data, _ := json.Marshal(body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[url] = data
}

func (m *mockMgmtGroupClient) onGetError(url string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[url] = err
}

func (m *mockMgmtGroupClient) Get(_ context.Context, url string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[url]++

	if err, ok := m.errors[url]; ok {
		return nil, err
	}
	if body, ok := m.responses[url]; ok {
		return body, nil
	}
	return nil, fmt.Errorf("no mock response for %s", url)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMgmtGroupsCollect_WithHierarchy(t *testing.T) {
	mock := newMockMgmtGroupClient()

	// List response: root + child management group.
	mock.onGet(mgmtGroupListURL, mgmtGroupListResponse{
		Value: []mgmtGroupListItem{
			{
				ID:   "/providers/Microsoft.Management/managementGroups/tenant-123",
				Name: "tenant-123",
				Properties: mgmtGroupListProperties{
					DisplayName: "Tenant Root Group",
					TenantID:    "tenant-123",
				},
			},
			{
				ID:   "/providers/Microsoft.Management/managementGroups/child-mg",
				Name: "child-mg",
				Properties: mgmtGroupListProperties{
					DisplayName: "Child MG",
					TenantID:    "tenant-123",
				},
			},
		},
	})

	// Expand response: root with child MG containing a subscription.
	expandURL := fmt.Sprintf(mgmtGroupExpandFmt, "tenant-123")
	mock.onGet(expandURL, mgmtGroupExpandResponse{
		ID:   "/providers/Microsoft.Management/managementGroups/tenant-123",
		Name: "tenant-123",
		Properties: mgmtGroupExpandProperties{
			DisplayName: "Tenant Root Group",
			TenantID:    "tenant-123",
			Children: []mgmtGroupChildNode{
				{
					ID:   "/providers/Microsoft.Management/managementGroups/child-mg",
					Name: "child-mg",
					Type: "/providers/Microsoft.Management/managementGroups",
					Properties: &mgmtGroupChildProperties{
						DisplayName: "Child MG",
					},
					Children: []mgmtGroupChildNode{
						{
							ID:   "/subscriptions/sub-1",
							Name: "sub-1",
							Type: "/subscriptions",
						},
					},
				},
			},
		},
	})

	collector := newMgmtGroupsCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())

	require.NoError(t, err)
	assert.Len(t, data.Groups, 2)
	assert.Len(t, data.Relationships, 2)

	// Root -> child-mg
	assert.Equal(t, "/providers/Microsoft.Management/managementGroups/tenant-123", data.Relationships[0].ParentID)
	assert.Equal(t, "/providers/Microsoft.Management/managementGroups/child-mg", data.Relationships[0].ChildID)
	assert.Equal(t, "managementGroup", data.Relationships[0].ChildType)

	// child-mg -> sub-1
	assert.Equal(t, "/providers/Microsoft.Management/managementGroups/child-mg", data.Relationships[1].ParentID)
	assert.Equal(t, "/subscriptions/sub-1", data.Relationships[1].ChildID)
	assert.Equal(t, "subscription", data.Relationships[1].ChildType)
}

func TestMgmtGroupsCollect_EmptyTenant(t *testing.T) {
	mock := newMockMgmtGroupClient()

	mock.onGet(mgmtGroupListURL, mgmtGroupListResponse{
		Value: []mgmtGroupListItem{},
	})

	collector := newMgmtGroupsCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())

	require.NoError(t, err)
	assert.Empty(t, data.Groups)
	assert.Empty(t, data.Relationships)
}

func TestMgmtGroupsCollect_ListFails(t *testing.T) {
	mock := newMockMgmtGroupClient()

	mock.onGetError(mgmtGroupListURL, fmt.Errorf("403 forbidden"))

	collector := newMgmtGroupsCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())

	require.NoError(t, err, "list failure should be non-fatal")
	assert.Empty(t, data.Groups)
	assert.Empty(t, data.Relationships)
}

func TestMgmtGroupsCollect_ExpandFails(t *testing.T) {
	mock := newMockMgmtGroupClient()

	mock.onGet(mgmtGroupListURL, mgmtGroupListResponse{
		Value: []mgmtGroupListItem{
			{
				ID:   "/providers/Microsoft.Management/managementGroups/tenant-123",
				Name: "tenant-123",
				Properties: mgmtGroupListProperties{
					DisplayName: "Tenant Root Group",
					TenantID:    "tenant-123",
				},
			},
		},
	})

	expandURL := fmt.Sprintf(mgmtGroupExpandFmt, "tenant-123")
	mock.onGetError(expandURL, fmt.Errorf("500 internal server error"))

	collector := newMgmtGroupsCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())

	require.NoError(t, err, "expand failure should be non-fatal")
	assert.Len(t, data.Groups, 1, "groups from list should still be present")
	assert.Empty(t, data.Relationships, "no relationships without expand")
}

func TestMgmtGroupsCollect_DeepHierarchy(t *testing.T) {
	mock := newMockMgmtGroupClient()

	// List: root + 3 child groups.
	mock.onGet(mgmtGroupListURL, mgmtGroupListResponse{
		Value: []mgmtGroupListItem{
			{ID: "/providers/Microsoft.Management/managementGroups/root", Name: "root",
				Properties: mgmtGroupListProperties{DisplayName: "Root", TenantID: "root"}},
			{ID: "/providers/Microsoft.Management/managementGroups/level1", Name: "level1",
				Properties: mgmtGroupListProperties{DisplayName: "Level 1", TenantID: "root"}},
			{ID: "/providers/Microsoft.Management/managementGroups/level2", Name: "level2",
				Properties: mgmtGroupListProperties{DisplayName: "Level 2", TenantID: "root"}},
			{ID: "/providers/Microsoft.Management/managementGroups/level3", Name: "level3",
				Properties: mgmtGroupListProperties{DisplayName: "Level 3", TenantID: "root"}},
		},
	})

	// Expand: root -> level1 -> level2 -> level3 -> subscription.
	expandURL := fmt.Sprintf(mgmtGroupExpandFmt, "root")
	mock.onGet(expandURL, mgmtGroupExpandResponse{
		ID:   "/providers/Microsoft.Management/managementGroups/root",
		Name: "root",
		Properties: mgmtGroupExpandProperties{
			DisplayName: "Root",
			TenantID:    "root",
			Children: []mgmtGroupChildNode{
				{
					ID: "/providers/Microsoft.Management/managementGroups/level1", Name: "level1",
					Type:       "/providers/Microsoft.Management/managementGroups",
					Properties: &mgmtGroupChildProperties{DisplayName: "Level 1"},
					Children: []mgmtGroupChildNode{
						{
							ID: "/providers/Microsoft.Management/managementGroups/level2", Name: "level2",
							Type:       "/providers/Microsoft.Management/managementGroups",
							Properties: &mgmtGroupChildProperties{DisplayName: "Level 2"},
							Children: []mgmtGroupChildNode{
								{
									ID: "/providers/Microsoft.Management/managementGroups/level3", Name: "level3",
									Type:       "/providers/Microsoft.Management/managementGroups",
									Properties: &mgmtGroupChildProperties{DisplayName: "Level 3"},
									Children: []mgmtGroupChildNode{
										{
											ID: "/subscriptions/sub-deep", Name: "sub-deep",
											Type: "/subscriptions",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})

	collector := newMgmtGroupsCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())

	require.NoError(t, err)
	assert.Len(t, data.Groups, 4)

	// 4 relationships: root->l1, l1->l2, l2->l3, l3->sub
	require.Len(t, data.Relationships, 4)

	assert.Equal(t, "managementGroup", data.Relationships[0].ChildType)
	assert.Equal(t, "managementGroup", data.Relationships[1].ChildType)
	assert.Equal(t, "managementGroup", data.Relationships[2].ChildType)
	assert.Equal(t, "subscription", data.Relationships[3].ChildType)

	// Verify chain.
	assert.Equal(t, "/providers/Microsoft.Management/managementGroups/root", data.Relationships[0].ParentID)
	assert.Equal(t, "/providers/Microsoft.Management/managementGroups/level1", data.Relationships[0].ChildID)

	assert.Equal(t, "/providers/Microsoft.Management/managementGroups/level1", data.Relationships[1].ParentID)
	assert.Equal(t, "/providers/Microsoft.Management/managementGroups/level2", data.Relationships[1].ChildID)

	assert.Equal(t, "/providers/Microsoft.Management/managementGroups/level2", data.Relationships[2].ParentID)
	assert.Equal(t, "/providers/Microsoft.Management/managementGroups/level3", data.Relationships[2].ChildID)

	assert.Equal(t, "/providers/Microsoft.Management/managementGroups/level3", data.Relationships[3].ParentID)
	assert.Equal(t, "/subscriptions/sub-deep", data.Relationships[3].ChildID)
}
