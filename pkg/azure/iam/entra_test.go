package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock GraphClient
// ---------------------------------------------------------------------------

// mockGraphClient is a test double for GraphClient. It returns pre-configured
// responses keyed by request path. If a path is registered in errors, the
// corresponding error is returned.
type mockGraphClient struct {
	mu        sync.Mutex
	responses map[string][]byte   // path -> JSON body
	errors    map[string]error    // path -> error
	calls     map[string]int      // path -> call count
}

func newMockGraphClient() *mockGraphClient {
	return &mockGraphClient{
		responses: make(map[string][]byte),
		errors:    make(map[string]error),
		calls:     make(map[string]int),
	}
}

// onGet registers a successful response for a given path.
func (m *mockGraphClient) onGet(path string, body any) {
	data, _ := json.Marshal(body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[path] = data
}

// onGetError registers an error response for a given path.
func (m *mockGraphClient) onGetError(path string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[path] = err
}

func (m *mockGraphClient) Get(_ context.Context, path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[path]++

	if err, ok := m.errors[path]; ok {
		return nil, err
	}
	if data, ok := m.responses[path]; ok {
		return data, nil
	}
	// Check for prefix match (pagination uses full URLs)
	for k, v := range m.responses {
		if strings.HasSuffix(path, k) || strings.Contains(path, k) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("no mock response for path: %s", path)
}

func (m *mockGraphClient) callCount(path string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[path]
}

// ---------------------------------------------------------------------------
// Helper to build Graph-style list responses
// ---------------------------------------------------------------------------

type graphListResponse struct {
	Value    any    `json:"value"`
	NextLink string `json:"@odata.nextLink,omitempty"`
}

// ---------------------------------------------------------------------------
// Test: Full Collect with populated data
// ---------------------------------------------------------------------------

func TestCollect_PopulatedTenant(t *testing.T) {
	mock := newMockGraphClient()

	// Tenant ID
	mock.onGet("/organization", graphListResponse{
		Value: []map[string]string{{"id": "tenant-123"}},
	})

	// Users
	mock.onGet("/users", graphListResponse{
		Value: []types.EntraUser{
			{ObjectID: "u1", DisplayName: "Alice", UserPrincipalName: "alice@example.com", AccountEnabled: true},
			{ObjectID: "u2", DisplayName: "Bob", UserPrincipalName: "bob@example.com", AccountEnabled: false},
		},
	})

	// Groups
	mock.onGet("/groups", graphListResponse{
		Value: []types.EntraGroup{
			{ObjectID: "g1", DisplayName: "Admins", SecurityEnabled: true},
		},
	})

	// Service Principals
	mock.onGet("/servicePrincipals", graphListResponse{
		Value: []types.EntraServicePrincipal{
			{ObjectID: "sp1", DisplayName: "MyApp SP", AppID: "app-id-1", ServicePrincipalType: "Application"},
		},
	})

	// Applications with owners
	mock.onGet("/applications?$expand=owners", graphListResponse{
		Value: []map[string]any{
			{
				"id":             "app1",
				"displayName":    "MyApp",
				"appId":          "app-id-1",
				"signInAudience": "AzureADMyOrg",
				"owners":         []map[string]string{{"id": "u1"}},
				"keyCredentials": []map[string]string{
					{"keyId": "key1", "displayName": "Cert1", "startDateTime": "2025-01-01", "endDateTime": "2026-01-01"},
				},
				"passwordCredentials": []map[string]string{
					{"keyId": "pwd1", "displayName": "Secret1", "startDateTime": "2025-01-01", "endDateTime": "2025-07-01"},
				},
			},
		},
	})

	// Devices
	mock.onGet("/devices", graphListResponse{
		Value: []types.EntraDevice{
			{ObjectID: "d1", DisplayName: "Laptop-1", OperatingSystem: "Windows"},
		},
	})

	// Directory Roles
	mock.onGet("/directoryRoles", graphListResponse{
		Value: []types.DirectoryRole{
			{ObjectID: "dr1", DisplayName: "Global Administrator", RoleTemplateID: "tmpl-1"},
		},
	})

	// Role Definitions
	mock.onGet("/roleManagement/directory/roleDefinitions", graphListResponse{
		Value: []types.EntraRoleDefinition{
			{ID: "rd1", DisplayName: "Global Admin", IsBuiltIn: true, IsEnabled: true},
		},
	})

	// Conditional Access Policies
	mock.onGet("/identity/conditionalAccess/policies", graphListResponse{
		Value: []types.ConditionalAccessPolicy{
			{ID: "cap1", DisplayName: "Block Legacy Auth", State: "enabled"},
		},
	})

	// Directory Role Assignments
	mock.onGet("/roleManagement/directory/roleAssignments", graphListResponse{
		Value: []types.DirectoryRoleAssignment{
			{ID: "dra1", PrincipalID: "u1", RoleDefinitionID: "rd1", DirectoryScopeID: "/"},
		},
	})

	// Group memberships (members of g1)
	mock.onGet("/groups/g1/members", graphListResponse{
		Value: []map[string]string{
			{"id": "u1", "@odata.type": "#microsoft.graph.user"},
		},
	})

	// OAuth2 Permission Grants
	mock.onGet("/oauth2PermissionGrants", graphListResponse{
		Value: []types.OAuth2PermissionGrant{
			{ID: "oauth1", ClientID: "sp1", ConsentType: "AllPrincipals", Scope: "User.Read"},
		},
	})

	// App Role Assignments (for sp1)
	mock.onGet("/servicePrincipals/sp1/appRoleAssignments", graphListResponse{
		Value: []types.AppRoleAssignment{
			{ID: "ara1", PrincipalID: "u1", ResourceID: "sp1", AppRoleID: "role1"},
		},
	})

	// Group ownership (for g1)
	mock.onGet("/groups/g1/owners", graphListResponse{
		Value: []map[string]string{{"id": "u2"}},
	})

	// SP ownership (for sp1)
	mock.onGet("/servicePrincipals/sp1/owners", graphListResponse{
		Value: []map[string]string{{"id": "u1"}},
	})

	collector := newEntraCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, data)

	// Verify tenant ID
	assert.Equal(t, "tenant-123", data.TenantID)

	// Verify users
	assert.Equal(t, 2, data.Users.Len())
	u1, ok := data.Users.Get("u1")
	require.True(t, ok)
	assert.Equal(t, "Alice", u1.DisplayName)

	// Verify groups
	assert.Equal(t, 1, data.Groups.Len())

	// Verify service principals
	assert.Equal(t, 1, data.ServicePrincipals.Len())

	// Verify applications
	assert.Equal(t, 1, data.Applications.Len())
	app1, ok := data.Applications.Get("app1")
	require.True(t, ok)
	assert.Equal(t, "MyApp", app1.DisplayName)

	// Verify devices
	assert.Len(t, data.Devices, 1)
	assert.Equal(t, "Laptop-1", data.Devices[0].DisplayName)

	// Verify directory roles
	assert.Len(t, data.DirectoryRoles, 1)

	// Verify role definitions
	assert.Len(t, data.RoleDefinitions, 1)

	// Verify conditional access policies
	assert.Len(t, data.ConditionalAccessPolicies, 1)

	// Verify directory role assignments
	assert.Len(t, data.DirectoryRoleAssignments, 1)

	// Verify group memberships
	assert.Len(t, data.GroupMemberships, 1)
	assert.Equal(t, "g1", data.GroupMemberships[0].GroupID)
	assert.Equal(t, "u1", data.GroupMemberships[0].MemberID)

	// Verify OAuth2 permission grants
	assert.Len(t, data.OAuth2PermissionGrants, 1)

	// Verify app role assignments
	assert.Len(t, data.AppRoleAssignments, 1)

	// Verify ownership relationships (app + group + SP)
	assert.GreaterOrEqual(t, len(data.OwnershipRelationships), 3)

	// Check specific ownership types
	var appOwners, groupOwners, spOwners int
	for _, o := range data.OwnershipRelationships {
		switch o.ResourceType {
		case "application":
			appOwners++
		case "group":
			groupOwners++
		case "servicePrincipal":
			spOwners++
		}
	}
	assert.Equal(t, 1, appOwners)
	assert.Equal(t, 1, groupOwners)
	assert.Equal(t, 1, spOwners)
}

// ---------------------------------------------------------------------------
// Test: Individual collection failures are non-fatal
// ---------------------------------------------------------------------------

func TestCollect_PartialFailure(t *testing.T) {
	mock := newMockGraphClient()

	// Tenant ID succeeds
	mock.onGet("/organization", graphListResponse{
		Value: []map[string]string{{"id": "tenant-456"}},
	})

	// Users fails
	mock.onGetError("/users", fmt.Errorf("403 forbidden"))

	// Groups succeeds
	mock.onGet("/groups", graphListResponse{
		Value: []types.EntraGroup{
			{ObjectID: "g1", DisplayName: "Engineers"},
		},
	})

	// All other endpoints fail
	mock.onGetError("/servicePrincipals", fmt.Errorf("timeout"))
	mock.onGetError("/applications?$expand=owners", fmt.Errorf("timeout"))
	mock.onGetError("/devices", fmt.Errorf("500 server error"))
	mock.onGetError("/directoryRoles", fmt.Errorf("500 server error"))
	mock.onGetError("/roleManagement/directory/roleDefinitions", fmt.Errorf("500"))
	mock.onGetError("/identity/conditionalAccess/policies", fmt.Errorf("500"))
	mock.onGetError("/roleManagement/directory/roleAssignments", fmt.Errorf("500"))
	mock.onGetError("/oauth2PermissionGrants", fmt.Errorf("500"))

	// Group member fetch for g1 succeeds
	mock.onGet("/groups/g1/members", graphListResponse{
		Value: []map[string]string{{"id": "u1", "@odata.type": "#microsoft.graph.user"}},
	})
	// Group owner fetch for g1 succeeds
	mock.onGet("/groups/g1/owners", graphListResponse{
		Value: []map[string]string{{"id": "u2"}},
	})

	collector := newEntraCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())

	// Should NOT error — partial failures are non-fatal
	require.NoError(t, err)
	require.NotNil(t, data)

	assert.Equal(t, "tenant-456", data.TenantID)
	assert.Equal(t, 0, data.Users.Len()) // failed
	assert.Equal(t, 1, data.Groups.Len())
	assert.Equal(t, 0, data.ServicePrincipals.Len()) // failed

	// Group memberships should still work since groups succeeded
	assert.Len(t, data.GroupMemberships, 1)
}

// ---------------------------------------------------------------------------
// Test: Tenant ID failure is fatal
// ---------------------------------------------------------------------------

func TestCollect_TenantIDFailure(t *testing.T) {
	mock := newMockGraphClient()
	mock.onGetError("/organization", fmt.Errorf("401 unauthorized"))

	collector := newEntraCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Contains(t, err.Error(), "resolving tenant ID")
}

// ---------------------------------------------------------------------------
// Test: Pagination
// ---------------------------------------------------------------------------

func TestCollect_Pagination(t *testing.T) {
	mock := newMockGraphClient()

	mock.onGet("/organization", graphListResponse{
		Value: []map[string]string{{"id": "tenant-789"}},
	})

	// First page of users — includes nextLink
	page1, _ := json.Marshal(graphListResponse{
		Value: []types.EntraUser{
			{ObjectID: "u1", DisplayName: "Alice", UserPrincipalName: "alice@example.com"},
		},
		NextLink: "https://graph.microsoft.com/v1.0/users?$skiptoken=page2",
	})
	mock.responses["/users"] = page1

	// Second page (nextLink points to full URL)
	page2, _ := json.Marshal(graphListResponse{
		Value: []types.EntraUser{
			{ObjectID: "u2", DisplayName: "Bob", UserPrincipalName: "bob@example.com"},
		},
	})
	mock.responses["https://graph.microsoft.com/v1.0/users?$skiptoken=page2"] = page2

	// Empty responses for everything else to avoid errors
	emptyResp := graphListResponse{Value: json.RawMessage("[]")}
	mock.onGet("/groups", emptyResp)
	mock.onGet("/servicePrincipals", emptyResp)
	mock.onGet("/applications?$expand=owners", emptyResp)
	mock.onGet("/devices", emptyResp)
	mock.onGet("/directoryRoles", emptyResp)
	mock.onGet("/roleManagement/directory/roleDefinitions", emptyResp)
	mock.onGet("/identity/conditionalAccess/policies", emptyResp)
	mock.onGet("/roleManagement/directory/roleAssignments", emptyResp)
	mock.onGet("/oauth2PermissionGrants", emptyResp)

	collector := newEntraCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err)

	// Should have both users from both pages
	assert.Equal(t, 2, data.Users.Len())
	_, ok := data.Users.Get("u1")
	assert.True(t, ok)
	_, ok = data.Users.Get("u2")
	assert.True(t, ok)
}

// ---------------------------------------------------------------------------
// Test: Empty tenant
// ---------------------------------------------------------------------------

func TestCollect_EmptyTenant(t *testing.T) {
	mock := newMockGraphClient()

	mock.onGet("/organization", graphListResponse{
		Value: []map[string]string{{"id": "empty-tenant"}},
	})

	emptyResp := graphListResponse{Value: json.RawMessage("[]")}
	mock.onGet("/users", emptyResp)
	mock.onGet("/groups", emptyResp)
	mock.onGet("/servicePrincipals", emptyResp)
	mock.onGet("/applications?$expand=owners", emptyResp)
	mock.onGet("/devices", emptyResp)
	mock.onGet("/directoryRoles", emptyResp)
	mock.onGet("/roleManagement/directory/roleDefinitions", emptyResp)
	mock.onGet("/identity/conditionalAccess/policies", emptyResp)
	mock.onGet("/roleManagement/directory/roleAssignments", emptyResp)
	mock.onGet("/oauth2PermissionGrants", emptyResp)

	collector := newEntraCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, data)

	assert.Equal(t, "empty-tenant", data.TenantID)
	assert.Equal(t, 0, data.Users.Len())
	assert.Equal(t, 0, data.Groups.Len())
	assert.Equal(t, 0, data.ServicePrincipals.Len())
	assert.Equal(t, 0, data.Applications.Len())
	assert.Empty(t, data.Devices)
	assert.Empty(t, data.DirectoryRoles)
	assert.Empty(t, data.RoleDefinitions)
	assert.Empty(t, data.ConditionalAccessPolicies)
	assert.Empty(t, data.DirectoryRoleAssignments)
	assert.Empty(t, data.GroupMemberships)
	assert.Empty(t, data.OAuth2PermissionGrants)
	assert.Empty(t, data.AppRoleAssignments)
	assert.Empty(t, data.OwnershipRelationships)
}

// ---------------------------------------------------------------------------
// Test: Credential enrichment from application response
// ---------------------------------------------------------------------------

func TestCollect_ApplicationCredentialEnrichment(t *testing.T) {
	mock := newMockGraphClient()

	mock.onGet("/organization", graphListResponse{
		Value: []map[string]string{{"id": "tenant-creds"}},
	})

	emptyResp := graphListResponse{Value: json.RawMessage("[]")}
	mock.onGet("/users", emptyResp)
	mock.onGet("/groups", emptyResp)
	mock.onGet("/servicePrincipals", emptyResp)
	mock.onGet("/devices", emptyResp)
	mock.onGet("/directoryRoles", emptyResp)
	mock.onGet("/roleManagement/directory/roleDefinitions", emptyResp)
	mock.onGet("/identity/conditionalAccess/policies", emptyResp)
	mock.onGet("/roleManagement/directory/roleAssignments", emptyResp)
	mock.onGet("/oauth2PermissionGrants", emptyResp)

	// Application with credentials
	mock.onGet("/applications?$expand=owners", graphListResponse{
		Value: []map[string]any{
			{
				"id":             "app-with-creds",
				"displayName":    "CredApp",
				"appId":          "cred-app-id",
				"signInAudience": "AzureADMultipleOrgs",
				"owners":         []map[string]string{},
				"keyCredentials": []map[string]string{
					{"keyId": "cert-1", "displayName": "MyCert", "startDateTime": "2025-01-01T00:00:00Z", "endDateTime": "2026-01-01T00:00:00Z"},
				},
				"passwordCredentials": []map[string]string{
					{"keyId": "secret-1", "displayName": "MySecret", "startDateTime": "2025-06-01T00:00:00Z", "endDateTime": "2025-12-01T00:00:00Z"},
					{"keyId": "secret-2", "displayName": "MySecret2", "startDateTime": "2025-03-01T00:00:00Z", "endDateTime": "2025-09-01T00:00:00Z"},
				},
			},
		},
	})

	collector := newEntraCollectorWithClient(mock)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err)

	app, ok := data.Applications.Get("app-with-creds")
	require.True(t, ok)
	assert.Equal(t, "CredApp", app.DisplayName)

	assert.Equal(t, "cred-app-id", app.AppID)
	// The application should have credentials enriched from keyCredentials + passwordCredentials
	require.Len(t, app.Credentials, 3)

	// First should be the certificate
	assert.Equal(t, "cert-1", app.Credentials[0].KeyID)
	assert.Equal(t, "certificate", app.Credentials[0].Type)
	assert.Equal(t, "MyCert", app.Credentials[0].DisplayName)

	// Then the two passwords
	assert.Equal(t, "secret-1", app.Credentials[1].KeyID)
	assert.Equal(t, "password", app.Credentials[1].Type)
	assert.Equal(t, "secret-2", app.Credentials[2].KeyID)
	assert.Equal(t, "password", app.Credentials[2].Type)
}

// ---------------------------------------------------------------------------
// Test: paginate function directly
// ---------------------------------------------------------------------------

func TestPaginate_SinglePage(t *testing.T) {
	mock := newMockGraphClient()
	mock.onGet("/test", graphListResponse{
		Value: []map[string]string{{"id": "item1"}, {"id": "item2"}},
	})

	type item struct {
		ID string `json:"id"`
	}

	items, err := paginate[item](context.Background(), mock, "/test")
	require.NoError(t, err)
	assert.Len(t, items, 2)
}

func TestPaginate_MultiPage(t *testing.T) {
	mock := newMockGraphClient()

	page1, _ := json.Marshal(graphListResponse{
		Value:    []map[string]string{{"id": "a"}},
		NextLink: "https://graph.microsoft.com/v1.0/test?$skip=1",
	})
	mock.responses["/test"] = page1

	page2, _ := json.Marshal(graphListResponse{
		Value:    []map[string]string{{"id": "b"}},
		NextLink: "https://graph.microsoft.com/v1.0/test?$skip=2",
	})
	mock.responses["https://graph.microsoft.com/v1.0/test?$skip=1"] = page2

	page3, _ := json.Marshal(graphListResponse{
		Value: []map[string]string{{"id": "c"}},
	})
	mock.responses["https://graph.microsoft.com/v1.0/test?$skip=2"] = page3

	type item struct {
		ID string `json:"id"`
	}

	items, err := paginate[item](context.Background(), mock, "/test")
	require.NoError(t, err)
	assert.Len(t, items, 3)
	assert.Equal(t, "a", items[0].ID)
	assert.Equal(t, "b", items[1].ID)
	assert.Equal(t, "c", items[2].ID)
}

func TestPaginate_ErrorReturnsPartialData(t *testing.T) {
	mock := newMockGraphClient()

	page1, _ := json.Marshal(graphListResponse{
		Value:    []map[string]string{{"id": "a"}},
		NextLink: "https://graph.microsoft.com/v1.0/test?$skip=1",
	})
	mock.responses["/test"] = page1

	// Second page errors
	mock.onGetError("https://graph.microsoft.com/v1.0/test?$skip=1", fmt.Errorf("network error"))

	type item struct {
		ID string `json:"id"`
	}

	items, err := paginate[item](context.Background(), mock, "/test")
	assert.Error(t, err)
	// Should still have the first page's data
	assert.Len(t, items, 1)
}
