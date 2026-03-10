package azure

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeFromEntraUser(t *testing.T) {
	user := types.EntraUser{
		ObjectID:          "user-001",
		DisplayName:       "Alice",
		UserPrincipalName: "alice@contoso.com",
		Mail:              "alice@contoso.com",
		AccountEnabled:    true,
		UserType:          "Member",
	}

	node := NodeFromEntraUser(user)

	// Check labels
	expectedLabels := []string{"User", "Principal", "Azure::EntraID::User"}
	if len(node.Labels) != len(expectedLabels) {
		t.Fatalf("expected %d labels, got %d", len(expectedLabels), len(node.Labels))
	}
	for i, l := range expectedLabels {
		if node.Labels[i] != l {
			t.Errorf("label[%d] = %q, want %q", i, node.Labels[i], l)
		}
	}

	// Check unique key
	if len(node.UniqueKey) != 1 || node.UniqueKey[0] != "id" {
		t.Errorf("UniqueKey = %v, want [\"id\"]", node.UniqueKey)
	}

	// Check properties
	if node.Properties["id"] != "user-001" {
		t.Errorf("id = %v, want %q", node.Properties["id"], "user-001")
	}
	if node.Properties["displayName"] != "Alice" {
		t.Errorf("displayName = %v, want %q", node.Properties["displayName"], "Alice")
	}
	if node.Properties["userPrincipalName"] != "alice@contoso.com" {
		t.Errorf("userPrincipalName = %v, want %q", node.Properties["userPrincipalName"], "alice@contoso.com")
	}
	if node.Properties["accountEnabled"] != true {
		t.Errorf("accountEnabled = %v, want true", node.Properties["accountEnabled"])
	}
	if node.Properties["_type"] != "User" {
		t.Errorf("_type = %v, want %q", node.Properties["_type"], "User")
	}
	if node.Properties["_resourceType"] != "Azure::EntraID::User" {
		t.Errorf("_resourceType = %v, want %q", node.Properties["_resourceType"], "Azure::EntraID::User")
	}
}

func TestNodeFromEntraGroup(t *testing.T) {
	group := types.EntraGroup{
		ObjectID:        "group-001",
		DisplayName:     "Engineering",
		SecurityEnabled: true,
	}

	node := NodeFromEntraGroup(group)

	expectedLabels := []string{"Group", "Azure::EntraID::Group"}
	if len(node.Labels) != len(expectedLabels) {
		t.Fatalf("expected %d labels, got %d", len(expectedLabels), len(node.Labels))
	}
	for i, l := range expectedLabels {
		if node.Labels[i] != l {
			t.Errorf("label[%d] = %q, want %q", i, node.Labels[i], l)
		}
	}

	if node.Properties["id"] != "group-001" {
		t.Errorf("id = %v, want %q", node.Properties["id"], "group-001")
	}
	if node.Properties["_type"] != "Group" {
		t.Errorf("_type = %v, want %q", node.Properties["_type"], "Group")
	}
}

func TestRelationshipFromGroupMembership(t *testing.T) {
	gm := types.GroupMembership{
		GroupID:    "group-001",
		MemberID:   "user-001",
		MemberType: "User",
	}

	rel := RelationshipFromGroupMembership(gm)

	if rel.Type != "MEMBER_OF" {
		t.Errorf("Type = %q, want %q", rel.Type, "MEMBER_OF")
	}
	if rel.StartNode.Properties["id"] != "user-001" {
		t.Errorf("StartNode id = %v, want %q", rel.StartNode.Properties["id"], "user-001")
	}
	if rel.EndNode.Properties["id"] != "group-001" {
		t.Errorf("EndNode id = %v, want %q", rel.EndNode.Properties["id"], "group-001")
	}
	if rel.Properties["memberType"] != "User" {
		t.Errorf("memberType = %v, want %q", rel.Properties["memberType"], "User")
	}
}

func TestRelationshipFromOwnership(t *testing.T) {
	o := types.OwnershipRelationship{
		OwnerID:      "user-001",
		ResourceID:   "app-001",
		ResourceType: "Application",
	}

	rel := RelationshipFromOwnership(o)

	if rel.Type != "OWNS" {
		t.Errorf("Type = %q, want %q", rel.Type, "OWNS")
	}
	if rel.StartNode.Properties["id"] != "user-001" {
		t.Errorf("StartNode id = %v, want %q", rel.StartNode.Properties["id"], "user-001")
	}
	if rel.EndNode.Properties["id"] != "app-001" {
		t.Errorf("EndNode id = %v, want %q", rel.EndNode.Properties["id"], "app-001")
	}
	if rel.Properties["resourceType"] != "Application" {
		t.Errorf("resourceType = %v, want %q", rel.Properties["resourceType"], "Application")
	}
}

func TestRelationshipFromPIMAssignment(t *testing.T) {
	// Active assignment
	active := types.PIMRoleAssignment{
		ID:               "pim-001",
		PrincipalID:      "user-001",
		RoleDefinitionID: "role-001",
		Scope:            "/",
		AssignmentType:   "active",
	}

	rel := RelationshipFromPIMAssignment(active)
	if rel.Type != "HAS_PERMISSION" {
		t.Errorf("active Type = %q, want %q", rel.Type, "HAS_PERMISSION")
	}
	if rel.Properties["source"] != "PIM" {
		t.Errorf("active source = %v, want %q", rel.Properties["source"], "PIM")
	}
	if rel.Properties["assignmentType"] != "active" {
		t.Errorf("active assignmentType = %v, want %q", rel.Properties["assignmentType"], "active")
	}

	// Eligible assignment
	eligible := types.PIMRoleAssignment{
		ID:               "pim-002",
		PrincipalID:      "user-002",
		RoleDefinitionID: "role-002",
		Scope:            "/",
		AssignmentType:   "eligible",
	}

	rel = RelationshipFromPIMAssignment(eligible)
	if rel.Type != "HAS_PERMISSION" {
		t.Errorf("eligible Type = %q, want %q", rel.Type, "HAS_PERMISSION")
	}
	if rel.Properties["source"] != "PIM" {
		t.Errorf("eligible source = %v, want %q", rel.Properties["source"], "PIM")
	}
	if rel.Properties["assignmentType"] != "eligible" {
		t.Errorf("eligible assignmentType = %v, want %q", rel.Properties["assignmentType"], "eligible")
	}
}

func TestRelationshipFromRBACAssignment(t *testing.T) {
	ra := types.RoleAssignment{
		ID:               "rbac-001",
		PrincipalID:      "user-001",
		RoleDefinitionID: "role-def-001",
		Scope:            "/subscriptions/sub-123",
		PrincipalType:    "User",
	}

	rel := RelationshipFromRBACAssignment(ra)

	if rel.Type != "HAS_PERMISSION" {
		t.Errorf("Type = %q, want %q", rel.Type, "HAS_PERMISSION")
	}
	// End node should be a subscription node
	found := false
	for _, l := range rel.EndNode.Labels {
		if l == "Subscription" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("EndNode labels = %v, expected to contain \"Subscription\"", rel.EndNode.Labels)
	}
	if rel.EndNode.Properties["id"] != "sub-123" {
		t.Errorf("EndNode id = %v, want %q", rel.EndNode.Properties["id"], "sub-123")
	}
	// StartNode should use User labels since PrincipalType = "User"
	expectedUserLabels := []string{"User", "Principal", "Azure::EntraID::User"}
	if !equalStringSlices(rel.StartNode.Labels, expectedUserLabels) {
		t.Errorf("StartNode labels = %v, want %v", rel.StartNode.Labels, expectedUserLabels)
	}

	// ServicePrincipal RBAC assignment should resolve to SP labels
	spRA := types.RoleAssignment{
		ID:               "rbac-002",
		PrincipalID:      "sp-001",
		RoleDefinitionID: "role-def-001",
		Scope:            "/subscriptions/sub-123",
		PrincipalType:    "ServicePrincipal",
	}
	spRel := RelationshipFromRBACAssignment(spRA)
	expectedSPLabels := []string{"ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"}
	if !equalStringSlices(spRel.StartNode.Labels, expectedSPLabels) {
		t.Errorf("SP StartNode labels = %v, want %v", spRel.StartNode.Labels, expectedSPLabels)
	}

	// Group RBAC assignment should resolve to Group labels
	grpRA := types.RoleAssignment{
		ID:               "rbac-003",
		PrincipalID:      "grp-001",
		RoleDefinitionID: "role-def-001",
		Scope:            "/subscriptions/sub-123",
		PrincipalType:    "Group",
	}
	grpRel := RelationshipFromRBACAssignment(grpRA)
	expectedGrpLabels := []string{"Group", "Azure::EntraID::Group"}
	if !equalStringSlices(grpRel.StartNode.Labels, expectedGrpLabels) {
		t.Errorf("Group StartNode labels = %v, want %v", grpRel.StartNode.Labels, expectedGrpLabels)
	}
}

// equalStringSlices checks if two string slices have the same elements (order-sensitive).
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRelationshipFromMgmtGroupHierarchy(t *testing.T) {
	// Subscription child
	rel := RelationshipFromMgmtGroupHierarchy(types.ManagementGroupRelationship{
		ParentID:  "mg-root",
		ChildID:   "sub-001",
		ChildType: "subscription",
	})

	if rel.Type != "CONTAINS" {
		t.Errorf("Type = %q, want %q", rel.Type, "CONTAINS")
	}
	found := false
	for _, l := range rel.EndNode.Labels {
		if l == "Subscription" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("subscription child: EndNode labels = %v, expected \"Subscription\"", rel.EndNode.Labels)
	}

	// Management group child
	rel = RelationshipFromMgmtGroupHierarchy(types.ManagementGroupRelationship{
		ParentID:  "mg-root",
		ChildID:   "mg-child",
		ChildType: "managementGroup",
	})
	found = false
	for _, l := range rel.EndNode.Labels {
		if l == "ManagementGroup" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("mg child: EndNode labels = %v, expected \"ManagementGroup\"", rel.EndNode.Labels)
	}
}

func TestTransformEntraIDData(t *testing.T) {
	data := types.NewEntraIDData(
		"tenant-001",
		[]types.EntraUser{
			{ObjectID: "u1", DisplayName: "User1", AccountEnabled: true},
			{ObjectID: "u2", DisplayName: "User2", AccountEnabled: true},
		},
		[]types.EntraGroup{
			{ObjectID: "g1", DisplayName: "Group1", SecurityEnabled: true},
		},
		[]types.EntraServicePrincipal{
			{ObjectID: "sp1", DisplayName: "SP1", AppID: "app-id-1"},
		},
		[]types.EntraApplication{
			{ObjectID: "a1", DisplayName: "App1", AppID: "app-id-1"},
		},
	)
	data.Devices = []types.EntraDevice{
		{ObjectID: "d1", DisplayName: "Device1"},
	}
	data.DirectoryRoles = []types.DirectoryRole{
		{ObjectID: "dr1", DisplayName: "Global Admin", RoleTemplateID: "tmpl-1"},
	}
	data.RoleDefinitions = []types.EntraRoleDefinition{
		{ID: "rd1", DisplayName: "Global Admin"},
	}
	data.GroupMemberships = []types.GroupMembership{
		{GroupID: "g1", MemberID: "u1", MemberType: "User"},
	}
	data.DirectoryRoleAssignments = []types.DirectoryRoleAssignment{
		{ID: "dra1", PrincipalID: "u1", RoleDefinitionID: "rd1"},
	}
	data.OwnershipRelationships = []types.OwnershipRelationship{
		{OwnerID: "u1", ResourceID: "a1", ResourceType: "Application"},
	}

	nodes, rels := TransformEntraIDData(data)

	// 2 users + 1 group + 1 sp + 1 app + 1 device + 1 dirRole + 1 roleDef = 8
	expectedNodes := 8
	if len(nodes) != expectedNodes {
		t.Errorf("got %d nodes, want %d", len(nodes), expectedNodes)
	}

	// 1 groupMembership + 1 dirRoleAssignment + 1 ownership = 3
	expectedRels := 3
	if len(rels) != expectedRels {
		t.Errorf("got %d relationships, want %d", len(rels), expectedRels)
	}
}

func TestTransformAll_Nil(t *testing.T) {
	nodes, rels := TransformAll(nil)
	if nodes != nil || rels != nil {
		t.Errorf("TransformAll(nil) should return nil, nil")
	}
}

func TestFlattenStruct(t *testing.T) {
	type sample struct {
		Name    string   `json:"name"`
		Count   int      `json:"count"`
		Enabled bool     `json:"enabled"`
		Tags    []string `json:"tags,omitempty"`
	}

	s := sample{
		Name:    "test",
		Count:   42,
		Enabled: true,
		Tags:    []string{"a", "b"},
	}

	props := flattenStruct(s)

	if props["name"] != "test" {
		t.Errorf("name = %v, want %q", props["name"], "test")
	}
	// JSON numbers are float64
	if props["count"] != float64(42) {
		t.Errorf("count = %v, want %v", props["count"], float64(42))
	}
	if props["enabled"] != true {
		t.Errorf("enabled = %v, want true", props["enabled"])
	}
	tags, ok := props["tags"].([]string)
	if !ok {
		t.Fatalf("tags type = %T, want []string", props["tags"])
	}
	if len(tags) != 2 || tags[0] != "a" || tags[1] != "b" {
		t.Errorf("tags = %v, want [a b]", tags)
	}
}

func TestFlattenStruct_NestedObject(t *testing.T) {
	// Nested objects should be serialized as JSON strings
	type inner struct {
		Key string `json:"key"`
	}
	type outer struct {
		Name  string `json:"name"`
		Inner inner  `json:"inner"`
	}

	o := outer{Name: "test", Inner: inner{Key: "val"}}
	props := flattenStruct(o)

	if props["name"] != "test" {
		t.Errorf("name = %v, want %q", props["name"], "test")
	}
	// inner should be a JSON string
	innerStr, ok := props["inner"].(string)
	if !ok {
		t.Fatalf("inner type = %T, want string", props["inner"])
	}
	if innerStr != `{"key":"val"}` {
		t.Errorf("inner = %q, want %q", innerStr, `{"key":"val"}`)
	}
}

// ---------------------------------------------------------------------------
// NodeFromEntraServicePrincipal
// ---------------------------------------------------------------------------

func TestNodeFromEntraServicePrincipal(t *testing.T) {
	sp := types.EntraServicePrincipal{
		ObjectID:             "sp-001",
		DisplayName:          "My Service Principal",
		AppID:                "app-id-001",
		ServicePrincipalType: "Application",
		AccountEnabled:       true,
		Tags:                 []string{"WindowsAzureActiveDirectoryIntegratedApp"},
	}

	node := NodeFromEntraServicePrincipal(sp)

	// Labels
	assert.Equal(t, []string{"ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"}, node.Labels)

	// UniqueKey
	assert.Equal(t, []string{"id"}, node.UniqueKey)

	// Properties
	assert.Equal(t, "sp-001", node.Properties["id"])
	assert.Equal(t, "My Service Principal", node.Properties["displayName"])
	assert.Equal(t, "app-id-001", node.Properties["appId"])
	assert.Equal(t, "Application", node.Properties["servicePrincipalType"])
	assert.Equal(t, true, node.Properties["accountEnabled"])
	assert.Equal(t, "ServicePrincipal", node.Properties["_type"])
	assert.Equal(t, "Azure::EntraID::ServicePrincipal", node.Properties["_resourceType"])

	// Tags should be flattened as []string
	tags, ok := node.Properties["tags"].([]string)
	require.True(t, ok, "tags should be []string, got %T", node.Properties["tags"])
	assert.Equal(t, []string{"WindowsAzureActiveDirectoryIntegratedApp"}, tags)
}

// ---------------------------------------------------------------------------
// NodeFromManagedIdentity
// ---------------------------------------------------------------------------

func TestNodeFromManagedIdentity(t *testing.T) {
	mi := types.ManagedIdentity{
		ID:             "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1",
		Name:           "mi-1",
		Location:       "eastus",
		PrincipalID:    "principal-001",
		ClientID:       "client-001",
		TenantID:       "tenant-001",
		SubscriptionID: "sub-1",
		ResourceGroup:  "rg1",
	}

	node := NodeFromManagedIdentity(mi)

	// Labels
	assert.Equal(t, []string{"ManagedIdentity", "Principal", "Azure::ManagedIdentity"}, node.Labels)

	// UniqueKey
	assert.Equal(t, []string{"id"}, node.UniqueKey)

	// Properties - id is lowercased by JSON tag
	assert.Equal(t, mi.ID, node.Properties["id"])
	assert.Equal(t, "mi-1", node.Properties["name"])
	assert.Equal(t, "eastus", node.Properties["location"])
	assert.Equal(t, "principal-001", node.Properties["principalId"])
	assert.Equal(t, "client-001", node.Properties["clientId"])
	assert.Equal(t, "tenant-001", node.Properties["tenantId"])
	assert.Equal(t, "sub-1", node.Properties["subscriptionId"])
	assert.Equal(t, "rg1", node.Properties["resourceGroup"])
	assert.Equal(t, "ManagedIdentity", node.Properties["_type"])
	assert.Equal(t, "Azure::ManagedIdentity", node.Properties["_resourceType"])
}

// ---------------------------------------------------------------------------
// NodeFromSubscription
// ---------------------------------------------------------------------------

func TestNodeFromSubscription(t *testing.T) {
	node := NodeFromSubscription("sub-abc-123")

	assert.Equal(t, []string{"Subscription", "Azure::Subscription"}, node.Labels)
	assert.Equal(t, []string{"id"}, node.UniqueKey)
	assert.Equal(t, "sub-abc-123", node.Properties["id"])
	assert.Equal(t, "Subscription", node.Properties["_type"])
	assert.Equal(t, "Azure::Subscription", node.Properties["_resourceType"])
}

// ---------------------------------------------------------------------------
// TransformManagedIdentityData
// ---------------------------------------------------------------------------

func TestTransformManagedIdentityData(t *testing.T) {
	t.Run("nil data returns nil", func(t *testing.T) {
		nodes, rels := TransformManagedIdentityData(nil)
		assert.Nil(t, nodes)
		assert.Nil(t, rels)
	})

	t.Run("user-assigned MI creates MI node and MI-to-SP relationship", func(t *testing.T) {
		data := &types.ManagedIdentityData{
			Identities: []types.ManagedIdentity{
				{
					ID:          "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1",
					Name:        "mi-1",
					Location:    "eastus",
					PrincipalID: "sp-principal-1",
					ClientID:    "client-1",
				},
			},
		}

		nodes, rels := TransformManagedIdentityData(data)

		// 1 ManagedIdentity node
		require.Len(t, nodes, 1)
		assert.Contains(t, nodes[0].Labels, "ManagedIdentity")
		assert.Equal(t, "mi-1", nodes[0].Properties["name"])

		// 1 MI -> SP CONTAINS relationship
		require.Len(t, rels, 1)
		assert.Equal(t, "CONTAINS", rels[0].Type)
		assert.Equal(t, "identity", rels[0].Properties["relationship"])
		assert.Equal(t, "sp-principal-1", rels[0].EndNode.Properties["id"])
		assert.Contains(t, rels[0].EndNode.Labels, "ServicePrincipal")
	})

	t.Run("system-assigned MI creates synthetic MI node, AzureResource node, and relationships", func(t *testing.T) {
		data := &types.ManagedIdentityData{
			Attachments: []types.ResourceIdentityAttachment{
				{
					ResourceID:   "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
					ResourceName: "vm-1",
					ResourceType: "Microsoft.Compute/virtualMachines",
					IdentityType: "SystemAssigned",
					PrincipalID:  "system-sp-principal",
				},
			},
		}

		nodes, rels := TransformManagedIdentityData(data)

		// 1 AzureResource node + 1 synthetic ManagedIdentity node = 2
		require.Len(t, nodes, 2)

		// Find AzureResource node
		var resourceNode, syntheticMINode = (*graph.Node)(nil), (*graph.Node)(nil)
		for _, n := range nodes {
			if n.Properties["_type"] == "AzureResource" {
				resourceNode = n
			}
			if n.Properties["_type"] == "ManagedIdentity" {
				syntheticMINode = n
			}
		}

		require.NotNil(t, resourceNode, "should have AzureResource node")
		assert.Contains(t, resourceNode.Labels, "AzureResource")
		assert.Equal(t, "vm-1", resourceNode.Properties["displayName"])

		require.NotNil(t, syntheticMINode, "should have synthetic ManagedIdentity node")
		assert.Contains(t, syntheticMINode.Labels, "ManagedIdentity")
		assert.Equal(t, true, syntheticMINode.Properties["_synthetic"])
		assert.Equal(t, "system-sp-principal", syntheticMINode.Properties["principalId"])

		// 1 resource->MI CONTAINS + 1 MI->SP CONTAINS = 2
		require.Len(t, rels, 2)

		// Resource -> MI
		resourceToMI := rels[0]
		assert.Equal(t, "CONTAINS", resourceToMI.Type)
		assert.Equal(t, "SystemAssigned", resourceToMI.Properties["identityType"])

		// MI -> SP
		miToSP := rels[1]
		assert.Equal(t, "CONTAINS", miToSP.Type)
		assert.Equal(t, "identity", miToSP.Properties["relationship"])
		assert.Equal(t, "system-sp-principal", miToSP.EndNode.Properties["id"])
	})

	t.Run("user-assigned attachment creates resource-to-MI relationship", func(t *testing.T) {
		data := &types.ManagedIdentityData{
			Attachments: []types.ResourceIdentityAttachment{
				{
					ResourceID:      "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Web/sites/app-1",
					ResourceName:    "app-1",
					ResourceType:    "Microsoft.Web/sites",
					IdentityType:    "UserAssigned",
					UserAssignedIDs: []string{"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1"},
				},
			},
		}

		nodes, rels := TransformManagedIdentityData(data)

		// 1 AzureResource node only (no synthetic MI for UserAssigned)
		require.Len(t, nodes, 1)
		assert.Contains(t, nodes[0].Labels, "AzureResource")

		// 1 resource -> MI CONTAINS relationship
		require.Len(t, rels, 1)
		assert.Equal(t, "CONTAINS", rels[0].Type)
		assert.Equal(t, "UserAssigned", rels[0].Properties["identityType"])
	})
}

// ---------------------------------------------------------------------------
// TransformRBACData
// ---------------------------------------------------------------------------

func TestTransformRBACData(t *testing.T) {
	t.Run("nil entries are skipped", func(t *testing.T) {
		nodes, rels := TransformRBACData([]*types.RBACData{nil, nil})
		assert.Empty(t, nodes)
		assert.Empty(t, rels)
	})

	t.Run("creates subscription nodes, role definition nodes, and HAS_PERMISSION edges", func(t *testing.T) {
		rbac := types.NewRBACData(
			"sub-001",
			[]types.RoleAssignment{
				{
					ID:               "ra-1",
					PrincipalID:      "user-1",
					RoleDefinitionID: "rd-1",
					Scope:            "/subscriptions/sub-001",
					PrincipalType:    "User",
				},
			},
			[]types.RoleDefinition{
				{
					ID:       "rd-1",
					RoleName: "Contributor",
					RoleType: "BuiltInRole",
					Permissions: []types.RolePermission{
						{Actions: []string{"*"}},
					},
				},
			},
		)

		nodes, rels := TransformRBACData([]*types.RBACData{rbac})

		// 1 Subscription + 1 RBACRoleDefinition = 2
		require.Len(t, nodes, 2)

		// Verify Subscription node
		var subNode, rdNode = (*graph.Node)(nil), (*graph.Node)(nil)
		for _, n := range nodes {
			switch {
			case n.Properties["_type"] == "Subscription":
				subNode = n
			case n.Properties["_type"] == "RBACRoleDefinition":
				rdNode = n
			}
		}

		require.NotNil(t, subNode)
		assert.Equal(t, "sub-001", subNode.Properties["id"])
		assert.Contains(t, subNode.Labels, "Subscription")

		require.NotNil(t, rdNode)
		assert.Equal(t, "rd-1", rdNode.Properties["id"])
		assert.Contains(t, rdNode.Labels, "RBACRoleDefinition")

		// 1 HAS_PERMISSION relationship
		require.Len(t, rels, 1)
		assert.Equal(t, "HAS_PERMISSION", rels[0].Type)
		assert.Equal(t, "Azure RBAC", rels[0].Properties["source"])
		assert.Equal(t, "user-1", rels[0].StartNode.Properties["id"])
	})

	t.Run("multiple subscriptions produce separate nodes", func(t *testing.T) {
		rbac1 := types.NewRBACData("sub-A", nil, nil)
		rbac2 := types.NewRBACData("sub-B", nil, nil)

		nodes, rels := TransformRBACData([]*types.RBACData{rbac1, rbac2})

		require.Len(t, nodes, 2)
		assert.Empty(t, rels)

		ids := []interface{}{nodes[0].Properties["id"], nodes[1].Properties["id"]}
		assert.Contains(t, ids, "sub-A")
		assert.Contains(t, ids, "sub-B")
	})
}

// ---------------------------------------------------------------------------
// principalNodeByType
// ---------------------------------------------------------------------------

func TestPrincipalNodeByType(t *testing.T) {
	tests := []struct {
		name           string
		odataType      string
		expectedLabels []string
	}{
		{
			name:           "group OData type",
			odataType:      "#microsoft.graph.group",
			expectedLabels: []string{"Group", "Azure::EntraID::Group"},
		},
		{
			name:           "serviceprincipal OData type",
			odataType:      "#microsoft.graph.servicePrincipal",
			expectedLabels: []string{"ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"},
		},
		{
			name:           "user OData type",
			odataType:      "#microsoft.graph.user",
			expectedLabels: []string{"User", "Principal", "Azure::EntraID::User"},
		},
		{
			name:           "unknown type defaults to User",
			odataType:      "#microsoft.graph.unknown",
			expectedLabels: []string{"User", "Principal", "Azure::EntraID::User"},
		},
		{
			name:           "empty string defaults to User",
			odataType:      "",
			expectedLabels: []string{"User", "Principal", "Azure::EntraID::User"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := principalNodeByType("test-id", tt.odataType)
			assert.Equal(t, tt.expectedLabels, node.Labels)
			assert.Equal(t, "test-id", node.Properties["id"])
			assert.Equal(t, []string{"id"}, node.UniqueKey)
		})
	}
}

// ---------------------------------------------------------------------------
// NodeFromEntraApplication
// ---------------------------------------------------------------------------

func TestNodeFromEntraApplication(t *testing.T) {
	app := types.EntraApplication{
		ObjectID:    "app-001",
		DisplayName: "My App",
		AppID:       "app-id-001",
	}

	node := NodeFromEntraApplication(app)

	assert.Equal(t, []string{"Application", "Azure::EntraID::Application"}, node.Labels)
	assert.Equal(t, []string{"id"}, node.UniqueKey)
	assert.Equal(t, "app-001", node.Properties["id"])
	assert.Equal(t, "My App", node.Properties["displayName"])
	assert.Equal(t, "app-id-001", node.Properties["appId"])
	assert.Equal(t, "Application", node.Properties["_type"])
	assert.Equal(t, "Azure::EntraID::Application", node.Properties["_resourceType"])
}

// ---------------------------------------------------------------------------
// NodeFromEntraDevice
// ---------------------------------------------------------------------------

func TestNodeFromEntraDevice(t *testing.T) {
	device := types.EntraDevice{
		ObjectID:        "dev-001",
		DisplayName:     "MyLaptop",
		OperatingSystem: "Windows",
		TrustType:       "AzureAD",
		AccountEnabled:  true,
	}

	node := NodeFromEntraDevice(device)

	assert.Equal(t, []string{"Device", "Azure::EntraID::Device"}, node.Labels)
	assert.Equal(t, []string{"id"}, node.UniqueKey)
	assert.Equal(t, "dev-001", node.Properties["id"])
	assert.Equal(t, "MyLaptop", node.Properties["displayName"])
	assert.Equal(t, "Windows", node.Properties["operatingSystem"])
	assert.Equal(t, "AzureAD", node.Properties["trustType"])
	assert.Equal(t, true, node.Properties["accountEnabled"])
	assert.Equal(t, "Device", node.Properties["_type"])
	assert.Equal(t, "Azure::EntraID::Device", node.Properties["_resourceType"])
}

// ---------------------------------------------------------------------------
// NodeFromDirectoryRole
// ---------------------------------------------------------------------------

func TestNodeFromDirectoryRole(t *testing.T) {
	role := types.DirectoryRole{
		ObjectID:       "dr-001",
		DisplayName:    "Global Administrator",
		RoleTemplateID: "tmpl-001",
	}

	node := NodeFromDirectoryRole(role)

	assert.Equal(t, []string{"DirectoryRole", "Azure::EntraID::DirectoryRole"}, node.Labels)
	assert.Equal(t, []string{"id"}, node.UniqueKey)
	assert.Equal(t, "dr-001", node.Properties["id"])
	assert.Equal(t, "Global Administrator", node.Properties["displayName"])
	assert.Equal(t, "tmpl-001", node.Properties["roleTemplateId"])
	assert.Equal(t, "DirectoryRole", node.Properties["_type"])
	assert.Equal(t, "Azure::EntraID::DirectoryRole", node.Properties["_resourceType"])
}

// ---------------------------------------------------------------------------
// NodeFromEntraRoleDefinition
// ---------------------------------------------------------------------------

func TestNodeFromEntraRoleDefinition(t *testing.T) {
	rd := types.EntraRoleDefinition{
		ID:          "rd-001",
		DisplayName: "Global Admin",
		IsBuiltIn:   true,
		IsEnabled:   true,
	}

	node := NodeFromEntraRoleDefinition(rd)

	assert.Equal(t, []string{"RoleDefinition", "Azure::EntraID::RoleDefinition"}, node.Labels)
	assert.Equal(t, []string{"id"}, node.UniqueKey)
	assert.Equal(t, "rd-001", node.Properties["id"])
	assert.Equal(t, "Global Admin", node.Properties["displayName"])
	assert.Equal(t, true, node.Properties["isBuiltIn"])
	assert.Equal(t, "RoleDefinition", node.Properties["_type"])
	assert.Equal(t, "Azure::EntraID::RoleDefinition", node.Properties["_resourceType"])
}

// ---------------------------------------------------------------------------
// NodeFromRBACRoleDefinition
// ---------------------------------------------------------------------------

func TestNodeFromRBACRoleDefinition(t *testing.T) {
	rd := types.RoleDefinition{
		ID:       "rbac-rd-001",
		RoleName: "Contributor",
		RoleType: "BuiltInRole",
	}

	node := NodeFromRBACRoleDefinition(rd)

	assert.Equal(t, []string{"RBACRoleDefinition", "Azure::RBAC::RoleDefinition"}, node.Labels)
	assert.Equal(t, []string{"id"}, node.UniqueKey)
	assert.Equal(t, "rbac-rd-001", node.Properties["id"])
	assert.Equal(t, "Contributor", node.Properties["roleName"])
	assert.Equal(t, "BuiltInRole", node.Properties["roleType"])
	assert.Equal(t, "RBACRoleDefinition", node.Properties["_type"])
	assert.Equal(t, "Azure::RBAC::RoleDefinition", node.Properties["_resourceType"])
}

// ---------------------------------------------------------------------------
// RelationshipFromDirectoryRoleAssignment
// ---------------------------------------------------------------------------

func TestRelationshipFromDirectoryRoleAssignment(t *testing.T) {
	t.Run("User principal", func(t *testing.T) {
		dra := types.DirectoryRoleAssignment{
			ID:               "dra-001",
			PrincipalID:      "user-001",
			RoleDefinitionID: "rd-001",
			DirectoryScopeID: "/",
			PrincipalType:    "User",
		}

		rel := RelationshipFromDirectoryRoleAssignment(dra)

		assert.Equal(t, "HAS_PERMISSION", rel.Type)
		assert.Equal(t, "Entra ID Directory Role", rel.Properties["source"])
		assert.Equal(t, "dra-001", rel.Properties["id"])
		assert.Equal(t, "/", rel.Properties["directoryScopeId"])
		assert.Equal(t, "user-001", rel.StartNode.Properties["id"])
		assert.Equal(t, []string{"User", "Principal", "Azure::EntraID::User"}, rel.StartNode.Labels)
		assert.Equal(t, "rd-001", rel.EndNode.Properties["id"])
		assert.Equal(t, []string{"RoleDefinition", "Azure::EntraID::RoleDefinition"}, rel.EndNode.Labels)
	})

	t.Run("Group principal", func(t *testing.T) {
		dra := types.DirectoryRoleAssignment{
			ID:               "dra-002",
			PrincipalID:      "group-001",
			RoleDefinitionID: "rd-001",
			PrincipalType:    "Group",
		}

		rel := RelationshipFromDirectoryRoleAssignment(dra)

		assert.Equal(t, []string{"Group", "Azure::EntraID::Group"}, rel.StartNode.Labels)
		assert.Equal(t, "group-001", rel.StartNode.Properties["id"])
	})

	t.Run("ServicePrincipal principal", func(t *testing.T) {
		dra := types.DirectoryRoleAssignment{
			ID:               "dra-003",
			PrincipalID:      "sp-001",
			RoleDefinitionID: "rd-001",
			PrincipalType:    "ServicePrincipal",
		}

		rel := RelationshipFromDirectoryRoleAssignment(dra)

		assert.Equal(t, []string{"ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"}, rel.StartNode.Labels)
		assert.Equal(t, "sp-001", rel.StartNode.Properties["id"])
	})

	t.Run("empty directoryScopeId omitted", func(t *testing.T) {
		dra := types.DirectoryRoleAssignment{
			ID:               "dra-004",
			PrincipalID:      "user-001",
			RoleDefinitionID: "rd-001",
			PrincipalType:    "User",
		}

		rel := RelationshipFromDirectoryRoleAssignment(dra)

		_, exists := rel.Properties["directoryScopeId"]
		assert.False(t, exists, "directoryScopeId should not be set when empty")
	})
}

// ---------------------------------------------------------------------------
// RelationshipFromAppRoleAssignment
// ---------------------------------------------------------------------------

func TestRelationshipFromAppRoleAssignment(t *testing.T) {
	t.Run("User principal", func(t *testing.T) {
		ara := types.AppRoleAssignment{
			ID:            "ara-001",
			PrincipalID:   "user-001",
			PrincipalType: "User",
			ResourceID:    "sp-resource-001",
			AppRoleID:     "role-001",
		}

		rel := RelationshipFromAppRoleAssignment(ara)

		assert.Equal(t, "HAS_PERMISSION", rel.Type)
		assert.Equal(t, "Microsoft Graph App Role", rel.Properties["source"])
		assert.Equal(t, "ara-001", rel.Properties["id"])
		assert.Equal(t, "role-001", rel.Properties["appRoleId"])
		assert.Equal(t, "user-001", rel.StartNode.Properties["id"])
		assert.Equal(t, []string{"User", "Principal", "Azure::EntraID::User"}, rel.StartNode.Labels)
		assert.Equal(t, "sp-resource-001", rel.EndNode.Properties["id"])
		assert.Contains(t, rel.EndNode.Labels, "ServicePrincipal")
	})

	t.Run("ServicePrincipal principal", func(t *testing.T) {
		ara := types.AppRoleAssignment{
			ID:            "ara-002",
			PrincipalID:   "sp-001",
			PrincipalType: "ServicePrincipal",
			ResourceID:    "sp-resource-001",
			AppRoleID:     "role-001",
		}

		rel := RelationshipFromAppRoleAssignment(ara)

		assert.Equal(t, []string{"ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"}, rel.StartNode.Labels)
	})

	t.Run("Group principal", func(t *testing.T) {
		ara := types.AppRoleAssignment{
			ID:            "ara-003",
			PrincipalID:   "group-001",
			PrincipalType: "Group",
			ResourceID:    "sp-resource-001",
			AppRoleID:     "role-001",
		}

		rel := RelationshipFromAppRoleAssignment(ara)

		assert.Equal(t, []string{"Group", "Azure::EntraID::Group"}, rel.StartNode.Labels)
	})
}

// ---------------------------------------------------------------------------
// RelationshipFromOAuth2Grant
// ---------------------------------------------------------------------------

func TestRelationshipFromOAuth2Grant(t *testing.T) {
	t.Run("with consent type", func(t *testing.T) {
		grant := types.OAuth2PermissionGrant{
			ID:          "grant-001",
			ClientID:    "sp-client-001",
			ConsentType: "AllPrincipals",
			ResourceID:  "sp-resource-001",
			Scope:       "User.Read Mail.Read",
		}

		rel := RelationshipFromOAuth2Grant(grant)

		assert.Equal(t, "HAS_PERMISSION", rel.Type)
		assert.Equal(t, "Microsoft Graph OAuth2", rel.Properties["source"])
		assert.Equal(t, "grant-001", rel.Properties["id"])
		assert.Equal(t, "User.Read Mail.Read", rel.Properties["scope"])
		assert.Equal(t, "AllPrincipals", rel.Properties["consentType"])
		assert.Equal(t, "sp-client-001", rel.StartNode.Properties["id"])
		assert.Contains(t, rel.StartNode.Labels, "ServicePrincipal")
		assert.Equal(t, "sp-resource-001", rel.EndNode.Properties["id"])
		assert.Contains(t, rel.EndNode.Labels, "ServicePrincipal")
	})

	t.Run("without consent type", func(t *testing.T) {
		grant := types.OAuth2PermissionGrant{
			ID:         "grant-002",
			ClientID:   "sp-client-001",
			ResourceID: "sp-resource-001",
			Scope:      "openid",
		}

		rel := RelationshipFromOAuth2Grant(grant)

		_, exists := rel.Properties["consentType"]
		assert.False(t, exists, "consentType should not be set when empty")
	})
}

// ---------------------------------------------------------------------------
// TransformPIMData
// ---------------------------------------------------------------------------

func TestTransformPIMData(t *testing.T) {
	t.Run("nil data returns nil", func(t *testing.T) {
		rels := TransformPIMData(nil)
		assert.Nil(t, rels)
	})

	t.Run("populated data produces relationships", func(t *testing.T) {
		data := &types.PIMData{
			ActiveAssignments: []types.PIMRoleAssignment{
				{
					ID:               "pim-active-1",
					PrincipalID:      "user-001",
					RoleDefinitionID: "rd-001",
					Scope:            "/",
					AssignmentType:   "active",
				},
			},
			EligibleAssignments: []types.PIMRoleAssignment{
				{
					ID:               "pim-eligible-1",
					PrincipalID:      "user-002",
					RoleDefinitionID: "rd-002",
					Scope:            "/",
					AssignmentType:   "eligible",
				},
				{
					ID:               "pim-eligible-2",
					PrincipalID:      "user-003",
					RoleDefinitionID: "rd-001",
					Scope:            "/",
					AssignmentType:   "eligible",
				},
			},
		}

		rels := TransformPIMData(data)

		require.Len(t, rels, 3)

		// First should be the active assignment
		assert.Equal(t, "active", rels[0].Properties["assignmentType"])
		assert.Equal(t, "PIM", rels[0].Properties["source"])
		assert.Equal(t, "HAS_PERMISSION", rels[0].Type)

		// Second and third should be eligible
		assert.Equal(t, "eligible", rels[1].Properties["assignmentType"])
		assert.Equal(t, "eligible", rels[2].Properties["assignmentType"])
	})
}

// ---------------------------------------------------------------------------
// TransformManagementGroupData
// ---------------------------------------------------------------------------

func TestTransformManagementGroupData(t *testing.T) {
	t.Run("nil data returns nil", func(t *testing.T) {
		nodes, rels := TransformManagementGroupData(nil)
		assert.Nil(t, nodes)
		assert.Nil(t, rels)
	})

	t.Run("populated data produces nodes and relationships", func(t *testing.T) {
		data := &types.ManagementGroupData{
			Groups: []types.ManagementGroup{
				{ID: "mg-root", DisplayName: "Root", Name: "root"},
				{ID: "mg-child", DisplayName: "Child", Name: "child"},
			},
			Relationships: []types.ManagementGroupRelationship{
				{ParentID: "mg-root", ChildID: "mg-child", ChildType: "managementGroup"},
				{ParentID: "mg-root", ChildID: "sub-001", ChildType: "subscription"},
			},
		}

		nodes, rels := TransformManagementGroupData(data)

		// 2 management group nodes
		require.Len(t, nodes, 2)
		assert.Contains(t, nodes[0].Labels, "ManagementGroup")
		assert.Contains(t, nodes[1].Labels, "ManagementGroup")
		assert.Equal(t, "mg-root", nodes[0].Properties["id"])
		assert.Equal(t, "mg-child", nodes[1].Properties["id"])

		// 2 CONTAINS relationships
		require.Len(t, rels, 2)
		assert.Equal(t, "CONTAINS", rels[0].Type)
		assert.Equal(t, "CONTAINS", rels[1].Type)

		// First rel: mg -> mg
		assert.Contains(t, rels[0].EndNode.Labels, "ManagementGroup")
		// Second rel: mg -> subscription
		assert.Contains(t, rels[1].EndNode.Labels, "Subscription")
	})
}

// ---------------------------------------------------------------------------
// RelationshipFromOwnership — additional resource type cases
// ---------------------------------------------------------------------------

func TestRelationshipFromOwnership_AllResourceTypes(t *testing.T) {
	t.Run("application resource type", func(t *testing.T) {
		rel := RelationshipFromOwnership(types.OwnershipRelationship{
			OwnerID: "user-001", ResourceID: "app-001", ResourceType: "Application",
		})
		assert.Equal(t, "OWNS", rel.Type)
		assert.Equal(t, []string{"Application", "Azure::EntraID::Application"}, rel.EndNode.Labels)
		assert.Equal(t, "app-001", rel.EndNode.Properties["id"])
	})

	t.Run("group resource type", func(t *testing.T) {
		rel := RelationshipFromOwnership(types.OwnershipRelationship{
			OwnerID: "user-001", ResourceID: "group-001", ResourceType: "group",
		})
		assert.Equal(t, "OWNS", rel.Type)
		assert.Equal(t, []string{"Group", "Azure::EntraID::Group"}, rel.EndNode.Labels)
		assert.Equal(t, "group-001", rel.EndNode.Properties["id"])
	})

	t.Run("serviceprincipal resource type", func(t *testing.T) {
		rel := RelationshipFromOwnership(types.OwnershipRelationship{
			OwnerID: "user-001", ResourceID: "sp-001", ResourceType: "serviceprincipal",
		})
		assert.Equal(t, "OWNS", rel.Type)
		assert.Equal(t, []string{"ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"}, rel.EndNode.Labels)
		assert.Equal(t, "sp-001", rel.EndNode.Properties["id"])
	})

	t.Run("unknown resource type defaults to Resource label", func(t *testing.T) {
		rel := RelationshipFromOwnership(types.OwnershipRelationship{
			OwnerID: "user-001", ResourceID: "res-001", ResourceType: "SomeOtherThing",
		})
		assert.Equal(t, "OWNS", rel.Type)
		assert.Equal(t, []string{"Resource"}, rel.EndNode.Labels)
		assert.Equal(t, "res-001", rel.EndNode.Properties["id"])
	})

	t.Run("start node is always a User node", func(t *testing.T) {
		rel := RelationshipFromOwnership(types.OwnershipRelationship{
			OwnerID: "owner-001", ResourceID: "res-001", ResourceType: "Application",
		})
		assert.Equal(t, []string{"User", "Principal", "Azure::EntraID::User"}, rel.StartNode.Labels)
		assert.Equal(t, "owner-001", rel.StartNode.Properties["id"])
	})
}

// ---------------------------------------------------------------------------
// principalNodeByAzureType
// ---------------------------------------------------------------------------

func TestPrincipalNodeByAzureType(t *testing.T) {
	tests := []struct {
		name           string
		principalType  string
		expectedLabels []string
	}{
		{
			name:           "Group type",
			principalType:  "Group",
			expectedLabels: []string{"Group", "Azure::EntraID::Group"},
		},
		{
			name:           "group lowercase",
			principalType:  "group",
			expectedLabels: []string{"Group", "Azure::EntraID::Group"},
		},
		{
			name:           "ServicePrincipal type",
			principalType:  "ServicePrincipal",
			expectedLabels: []string{"ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"},
		},
		{
			name:           "serviceprincipal lowercase",
			principalType:  "serviceprincipal",
			expectedLabels: []string{"ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"},
		},
		{
			name:           "User type",
			principalType:  "User",
			expectedLabels: []string{"User", "Principal", "Azure::EntraID::User"},
		},
		{
			name:           "unknown type defaults to User",
			principalType:  "ForeignGroup",
			expectedLabels: []string{"User", "Principal", "Azure::EntraID::User"},
		},
		{
			name:           "empty string defaults to User",
			principalType:  "",
			expectedLabels: []string{"User", "Principal", "Azure::EntraID::User"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := principalNodeByAzureType("test-id", tt.principalType)
			assert.Equal(t, tt.expectedLabels, node.Labels)
			assert.Equal(t, "test-id", node.Properties["id"])
			assert.Equal(t, []string{"id"}, node.UniqueKey)
		})
	}
}
