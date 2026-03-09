package azure

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
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
	if rel.Type != "HAS_PIM_ROLE" {
		t.Errorf("active Type = %q, want %q", rel.Type, "HAS_PIM_ROLE")
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
	if rel.Type != "ELIGIBLE_FOR_PIM_ROLE" {
		t.Errorf("eligible Type = %q, want %q", rel.Type, "ELIGIBLE_FOR_PIM_ROLE")
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

	if rel.Type != "HAS_RBAC_ROLE" {
		t.Errorf("Type = %q, want %q", rel.Type, "HAS_RBAC_ROLE")
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
