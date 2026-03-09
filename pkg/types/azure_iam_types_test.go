package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntraIDDataRoundTrip(t *testing.T) {
	t.Run("users and groups survive JSON round-trip", func(t *testing.T) {
		original := NewEntraIDData(
			"tenant-123",
			[]EntraUser{
				{ObjectID: "user-1", DisplayName: "Alice", UserPrincipalName: "alice@contoso.com", AccountEnabled: true},
				{ObjectID: "user-2", DisplayName: "Bob", UserPrincipalName: "bob@contoso.com", AccountEnabled: false},
			},
			[]EntraGroup{
				{ObjectID: "group-1", DisplayName: "Admins", SecurityEnabled: true},
			},
			[]EntraServicePrincipal{
				{ObjectID: "sp-1", DisplayName: "MyApp SP", AppID: "app-id-1", ServicePrincipalType: "Application"},
			},
			[]EntraApplication{
				{ObjectID: "app-1", DisplayName: "MyApp", AppID: "app-id-1"},
			},
		)
		original.Devices = []EntraDevice{{ObjectID: "dev-1", DisplayName: "Laptop1", OperatingSystem: "Windows"}}
		original.DirectoryRoles = []DirectoryRole{{ObjectID: "role-1", DisplayName: "Global Administrator", RoleTemplateID: "tmpl-1"}}
		original.RoleDefinitions = []EntraRoleDefinition{{ID: "roledef-1", DisplayName: "Custom Role"}}
		original.ConditionalAccessPolicies = []ConditionalAccessPolicy{{ID: "cap-1", DisplayName: "MFA Policy", State: "enabled"}}
		original.DirectoryRoleAssignments = []DirectoryRoleAssignment{{ID: "dra-1", PrincipalID: "user-1", RoleDefinitionID: "roledef-1"}}
		original.GroupMemberships = []GroupMembership{
			{GroupID: "group-1", MemberID: "user-1", MemberType: "user"},
		}
		original.OAuth2PermissionGrants = []OAuth2PermissionGrant{{ID: "grant-1", ClientID: "sp-1", Scope: "User.Read"}}
		original.AppRoleAssignments = []AppRoleAssignment{{ID: "ara-1", PrincipalID: "user-1", ResourceID: "sp-1", AppRoleID: "role-1"}}
		original.OwnershipRelationships = []OwnershipRelationship{{OwnerID: "user-1", ResourceID: "app-1", ResourceType: "application"}}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored EntraIDData
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		// Verify store.Map fields
		assert.Equal(t, 2, restored.Users.Len())
		alice, ok := restored.Users.Get("user-1")
		require.True(t, ok)
		assert.Equal(t, "Alice", alice.DisplayName)
		assert.Equal(t, "alice@contoso.com", alice.UserPrincipalName)
		assert.True(t, alice.AccountEnabled)

		bob, ok := restored.Users.Get("user-2")
		require.True(t, ok)
		assert.Equal(t, "Bob", bob.DisplayName)
		assert.False(t, bob.AccountEnabled)

		assert.Equal(t, 1, restored.Groups.Len())
		grp, ok := restored.Groups.Get("group-1")
		require.True(t, ok)
		assert.Equal(t, "Admins", grp.DisplayName)
		assert.True(t, grp.SecurityEnabled)

		assert.Equal(t, 1, restored.ServicePrincipals.Len())
		sp, ok := restored.ServicePrincipals.Get("sp-1")
		require.True(t, ok)
		assert.Equal(t, "MyApp SP", sp.DisplayName)

		assert.Equal(t, 1, restored.Applications.Len())
		app, ok := restored.Applications.Get("app-1")
		require.True(t, ok)
		assert.Equal(t, "MyApp", app.DisplayName)

		// Verify slice fields
		require.Len(t, restored.Devices, 1)
		assert.Equal(t, "Laptop1", restored.Devices[0].DisplayName)

		require.Len(t, restored.DirectoryRoles, 1)
		assert.Equal(t, "Global Administrator", restored.DirectoryRoles[0].DisplayName)

		require.Len(t, restored.RoleDefinitions, 1)
		assert.Equal(t, "Custom Role", restored.RoleDefinitions[0].DisplayName)

		require.Len(t, restored.ConditionalAccessPolicies, 1)
		assert.Equal(t, "MFA Policy", restored.ConditionalAccessPolicies[0].DisplayName)

		require.Len(t, restored.DirectoryRoleAssignments, 1)
		assert.Equal(t, "user-1", restored.DirectoryRoleAssignments[0].PrincipalID)

		require.Len(t, restored.GroupMemberships, 1)
		assert.Equal(t, "group-1", restored.GroupMemberships[0].GroupID)

		require.Len(t, restored.OAuth2PermissionGrants, 1)
		assert.Equal(t, "User.Read", restored.OAuth2PermissionGrants[0].Scope)

		require.Len(t, restored.AppRoleAssignments, 1)
		assert.Equal(t, "sp-1", restored.AppRoleAssignments[0].ResourceID)

		require.Len(t, restored.OwnershipRelationships, 1)
		assert.Equal(t, "application", restored.OwnershipRelationships[0].ResourceType)

		assert.Equal(t, "tenant-123", restored.TenantID)
	})

	t.Run("empty EntraIDData round-trips", func(t *testing.T) {
		original := NewEntraIDData("tenant-empty", nil, nil, nil, nil)

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored EntraIDData
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.Equal(t, 0, restored.Users.Len())
		assert.Equal(t, 0, restored.Groups.Len())
		assert.Equal(t, 0, restored.ServicePrincipals.Len())
		assert.Equal(t, 0, restored.Applications.Len())
		assert.Equal(t, "tenant-empty", restored.TenantID)
	})
}

func TestAzureIAMConsolidatedRoundTrip(t *testing.T) {
	t.Run("consolidated data round-trips through JSON", func(t *testing.T) {
		original := &AzureIAMConsolidated{
			EntraID: NewEntraIDData(
				"tenant-1",
				[]EntraUser{{ObjectID: "user-1", DisplayName: "Alice", UserPrincipalName: "alice@contoso.com"}},
				nil, nil, nil,
			),
			PIM: &PIMData{
				ActiveAssignments:   []PIMRoleAssignment{{ID: "pim-1", PrincipalID: "user-1", RoleDefinitionID: "role-1", Scope: "/subscriptions/sub-1", AssignmentType: "active"}},
				EligibleAssignments: []PIMRoleAssignment{{ID: "pim-2", PrincipalID: "user-1", RoleDefinitionID: "role-2", Scope: "/subscriptions/sub-1", AssignmentType: "eligible"}},
			},
			RBAC: []*RBACData{
				NewRBACData(
					"sub-1",
					[]RoleAssignment{{ID: "ra-1", PrincipalID: "user-1", RoleDefinitionID: "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7", Scope: "/subscriptions/sub-1"}},
					[]RoleDefinition{{ID: "acdd72a7", RoleName: "Reader", RoleType: "BuiltInRole", Permissions: []RolePermission{{Actions: []string{"*/read"}}}}},
				),
			},
			ManagementGroups: &ManagementGroupData{
				Groups:        []ManagementGroup{{ID: "mg-1", DisplayName: "Root MG", Name: "root"}},
				Relationships: []ManagementGroupRelationship{{ParentID: "mg-1", ChildID: "sub-1", ChildType: "subscription"}},
			},
			Metadata: &CollectionMetadata{
				TenantID:  "tenant-1",
				Timestamp: "2026-03-09T00:00:00Z",
				Counts:    map[string]int{"users": 1, "roleAssignments": 1},
			},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored AzureIAMConsolidated
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		// Verify EntraID
		assert.Equal(t, 1, restored.EntraID.Users.Len())
		alice, ok := restored.EntraID.Users.Get("user-1")
		require.True(t, ok)
		assert.Equal(t, "Alice", alice.DisplayName)

		// Verify PIM
		require.Len(t, restored.PIM.ActiveAssignments, 1)
		assert.Equal(t, "active", restored.PIM.ActiveAssignments[0].AssignmentType)
		require.Len(t, restored.PIM.EligibleAssignments, 1)
		assert.Equal(t, "eligible", restored.PIM.EligibleAssignments[0].AssignmentType)

		// Verify RBAC
		require.Len(t, restored.RBAC, 1)
		assert.Equal(t, "sub-1", restored.RBAC[0].SubscriptionID)
		require.Len(t, restored.RBAC[0].Assignments, 1)
		assert.Equal(t, "user-1", restored.RBAC[0].Assignments[0].PrincipalID)
		rdDef, ok := restored.RBAC[0].Definitions.Get("acdd72a7")
		require.True(t, ok)
		assert.Equal(t, "Reader", rdDef.RoleName)

		// Verify Management Groups
		require.Len(t, restored.ManagementGroups.Groups, 1)
		assert.Equal(t, "Root MG", restored.ManagementGroups.Groups[0].DisplayName)
		require.Len(t, restored.ManagementGroups.Relationships, 1)
		assert.Equal(t, "subscription", restored.ManagementGroups.Relationships[0].ChildType)

		// Verify Metadata
		assert.Equal(t, "tenant-1", restored.Metadata.TenantID)
		assert.Equal(t, "2026-03-09T00:00:00Z", restored.Metadata.Timestamp)
		assert.Equal(t, 1, restored.Metadata.Counts["users"])
	})
}

func TestRBACDataRoundTrip(t *testing.T) {
	t.Run("store.Map[RoleDefinition] round-trips", func(t *testing.T) {
		original := NewRBACData(
			"sub-abc",
			[]RoleAssignment{
				{ID: "ra-1", PrincipalID: "user-1", RoleDefinitionID: "rd-1", Scope: "/subscriptions/sub-abc"},
				{ID: "ra-2", PrincipalID: "sp-1", RoleDefinitionID: "rd-2", Scope: "/subscriptions/sub-abc/resourceGroups/rg1"},
			},
			[]RoleDefinition{
				{
					ID:       "rd-1",
					RoleName: "Contributor",
					RoleType: "BuiltInRole",
					Permissions: []RolePermission{
						{Actions: []string{"*"}, NotActions: []string{"Microsoft.Authorization/*/Delete"}},
					},
				},
				{
					ID:       "rd-2",
					RoleName: "Custom Reader",
					RoleType: "CustomRole",
					Permissions: []RolePermission{
						{Actions: []string{"*/read"}, DataActions: []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}},
					},
				},
			},
		)
		original.HighValueResources = []HighValueResource{
			{ResourceID: "/subscriptions/sub-abc/resourceGroups/rg1", ResourceType: "Microsoft.KeyVault/vaults", Reason: "Contains secrets"},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored RBACData
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.Equal(t, "sub-abc", restored.SubscriptionID)
		require.Len(t, restored.Assignments, 2)
		assert.Equal(t, "user-1", restored.Assignments[0].PrincipalID)

		assert.Equal(t, 2, restored.Definitions.Len())
		contrib, ok := restored.Definitions.Get("rd-1")
		require.True(t, ok)
		assert.Equal(t, "Contributor", contrib.RoleName)
		require.Len(t, contrib.Permissions, 1)
		assert.Equal(t, []string{"*"}, contrib.Permissions[0].Actions)
		assert.Equal(t, []string{"Microsoft.Authorization/*/Delete"}, contrib.Permissions[0].NotActions)

		custom, ok := restored.Definitions.Get("rd-2")
		require.True(t, ok)
		assert.Equal(t, "Custom Reader", custom.RoleName)
		assert.Equal(t, "CustomRole", custom.RoleType)
		require.Len(t, custom.Permissions, 1)
		assert.Equal(t, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}, custom.Permissions[0].DataActions)

		require.Len(t, restored.HighValueResources, 1)
		assert.Equal(t, "Contains secrets", restored.HighValueResources[0].Reason)
	})

	t.Run("empty RBACData round-trips", func(t *testing.T) {
		original := NewRBACData("sub-empty", nil, nil)

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored RBACData
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.Equal(t, "sub-empty", restored.SubscriptionID)
		assert.Equal(t, 0, restored.Definitions.Len())
	})
}
