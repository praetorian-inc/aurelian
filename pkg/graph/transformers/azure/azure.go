package azure

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ---------------------------------------------------------------------------
// Node constructors
// ---------------------------------------------------------------------------

// NodeFromEntraUser creates a graph node from an Entra ID user.
// Labels: ["User", "Principal", "Azure::EntraID::User"]
// UniqueKey: ["id"]
func NodeFromEntraUser(user types.EntraUser) *graph.Node {
	props := flattenStruct(user)
	props["_type"] = "User"
	props["_resourceType"] = "Azure::EntraID::User"

	return &graph.Node{
		Labels:     []string{"User", "Principal", "Azure::EntraID::User"},
		Properties: props,
		UniqueKey:  []string{"id"},
	}
}

// NodeFromEntraGroup creates a graph node from an Entra ID group.
// Labels: ["Group", "Azure::EntraID::Group"]
// UniqueKey: ["id"]
func NodeFromEntraGroup(group types.EntraGroup) *graph.Node {
	props := flattenStruct(group)
	props["_type"] = "Group"
	props["_resourceType"] = "Azure::EntraID::Group"

	return &graph.Node{
		Labels:     []string{"Group", "Azure::EntraID::Group"},
		Properties: props,
		UniqueKey:  []string{"id"},
	}
}

// NodeFromEntraServicePrincipal creates a graph node from an Entra ID service principal.
// Labels: ["ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"]
// UniqueKey: ["id"]
func NodeFromEntraServicePrincipal(sp types.EntraServicePrincipal) *graph.Node {
	props := flattenStruct(sp)
	props["_type"] = "ServicePrincipal"
	props["_resourceType"] = "Azure::EntraID::ServicePrincipal"

	return &graph.Node{
		Labels:     []string{"ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"},
		Properties: props,
		UniqueKey:  []string{"id"},
	}
}

// NodeFromEntraApplication creates a graph node from an Entra ID application registration.
// Labels: ["Application", "Azure::EntraID::Application"]
// UniqueKey: ["id"]
func NodeFromEntraApplication(app types.EntraApplication) *graph.Node {
	props := flattenStruct(app)
	props["_type"] = "Application"
	props["_resourceType"] = "Azure::EntraID::Application"

	return &graph.Node{
		Labels:     []string{"Application", "Azure::EntraID::Application"},
		Properties: props,
		UniqueKey:  []string{"id"},
	}
}

// NodeFromEntraDevice creates a graph node from an Entra ID device.
// Labels: ["Device", "Azure::EntraID::Device"]
// UniqueKey: ["id"]
func NodeFromEntraDevice(device types.EntraDevice) *graph.Node {
	props := flattenStruct(device)
	props["_type"] = "Device"
	props["_resourceType"] = "Azure::EntraID::Device"

	return &graph.Node{
		Labels:     []string{"Device", "Azure::EntraID::Device"},
		Properties: props,
		UniqueKey:  []string{"id"},
	}
}

// NodeFromDirectoryRole creates a graph node from an activated Entra ID directory role.
// Labels: ["DirectoryRole", "Azure::EntraID::DirectoryRole"]
// UniqueKey: ["id"]
func NodeFromDirectoryRole(role types.DirectoryRole) *graph.Node {
	props := flattenStruct(role)
	props["_type"] = "DirectoryRole"
	props["_resourceType"] = "Azure::EntraID::DirectoryRole"

	return &graph.Node{
		Labels:     []string{"DirectoryRole", "Azure::EntraID::DirectoryRole"},
		Properties: props,
		UniqueKey:  []string{"id"},
	}
}

// NodeFromEntraRoleDefinition creates a graph node from an Entra ID role definition.
// Labels: ["RoleDefinition", "Azure::EntraID::RoleDefinition"]
// UniqueKey: ["id"]
func NodeFromEntraRoleDefinition(rd types.EntraRoleDefinition) *graph.Node {
	props := flattenStruct(rd)
	props["_type"] = "RoleDefinition"
	props["_resourceType"] = "Azure::EntraID::RoleDefinition"

	return &graph.Node{
		Labels:     []string{"RoleDefinition", "Azure::EntraID::RoleDefinition"},
		Properties: props,
		UniqueKey:  []string{"id"},
	}
}

// NodeFromManagementGroup creates a graph node from an Azure management group.
// Labels: ["ManagementGroup", "Azure::Management::ManagementGroup"]
// UniqueKey: ["id"]
func NodeFromManagementGroup(mg types.ManagementGroup) *graph.Node {
	props := flattenStruct(mg)
	props["_type"] = "ManagementGroup"
	props["_resourceType"] = "Azure::Management::ManagementGroup"

	return &graph.Node{
		Labels:     []string{"ManagementGroup", "Azure::Management::ManagementGroup"},
		Properties: props,
		UniqueKey:  []string{"id"},
	}
}

// NodeFromSubscription creates a minimal graph node for an Azure subscription from its ID.
// Labels: ["Subscription", "Azure::Subscription"]
// UniqueKey: ["id"]
func NodeFromSubscription(subID string) *graph.Node {
	return &graph.Node{
		Labels: []string{"Subscription", "Azure::Subscription"},
		Properties: map[string]interface{}{
			"id":            subID,
			"_type":         "Subscription",
			"_resourceType": "Azure::Subscription",
		},
		UniqueKey: []string{"id"},
	}
}

// NodeFromRBACRoleDefinition creates a graph node from an Azure RBAC role definition.
// Labels: ["RBACRoleDefinition", "Azure::RBAC::RoleDefinition"]
// UniqueKey: ["id"]
func NodeFromRBACRoleDefinition(rd types.RoleDefinition) *graph.Node {
	props := flattenStruct(rd)
	props["_type"] = "RBACRoleDefinition"
	props["_resourceType"] = "Azure::RBAC::RoleDefinition"

	return &graph.Node{
		Labels:     []string{"RBACRoleDefinition", "Azure::RBAC::RoleDefinition"},
		Properties: props,
		UniqueKey:  []string{"id"},
	}
}

// ---------------------------------------------------------------------------
// Relationship constructors
// ---------------------------------------------------------------------------

// RelationshipFromGroupMembership creates a MEMBER_OF relationship.
// StartNode: minimal Principal node with ID = gm.MemberID
// EndNode: minimal Group node with ID = gm.GroupID
func RelationshipFromGroupMembership(gm types.GroupMembership) *graph.Relationship {
	return &graph.Relationship{
		Type:       "MEMBER_OF",
		Properties: map[string]interface{}{"memberType": gm.MemberType},
		StartNode:  principalNodeByType(gm.MemberID, gm.MemberType),
		EndNode:    minimalGroupNode(gm.GroupID),
	}
}

// RelationshipFromDirectoryRoleAssignment creates a HAS_PERMISSION relationship
// for Entra ID directory role assignments.
func RelationshipFromDirectoryRoleAssignment(dra types.DirectoryRoleAssignment) *graph.Relationship {
	props := map[string]interface{}{
		"id":     dra.ID,
		"source": "Entra ID Directory Role",
	}
	if dra.DirectoryScopeID != "" {
		props["directoryScopeId"] = dra.DirectoryScopeID
	}

	return &graph.Relationship{
		Type:       "HAS_PERMISSION",
		Properties: props,
		StartNode:  principalNodeByAzureType(dra.PrincipalID, dra.PrincipalType),
		EndNode:    minimalRoleDefinitionNode(dra.RoleDefinitionID),
	}
}

// RelationshipFromOwnership creates an OWNS relationship.
// StartNode: minimal Principal node with ID = o.OwnerID
// EndNode: minimal node with ID = o.ResourceID
func RelationshipFromOwnership(o types.OwnershipRelationship) *graph.Relationship {
	// Resolve end node labels based on resource type to match full node labels.
	var endNode *graph.Node
	switch strings.ToLower(o.ResourceType) {
	case "application":
		endNode = &graph.Node{
			Labels:     []string{"Application", "Azure::EntraID::Application"},
			Properties: map[string]interface{}{"id": o.ResourceID},
			UniqueKey:  []string{"id"},
		}
	case "group":
		endNode = minimalGroupNode(o.ResourceID)
	case "serviceprincipal":
		endNode = minimalServicePrincipalNode(o.ResourceID)
	default:
		endNode = &graph.Node{
			Labels:     []string{"Resource"},
			Properties: map[string]interface{}{"id": o.ResourceID},
			UniqueKey:  []string{"id"},
		}
	}

	return &graph.Relationship{
		Type:       "OWNS",
		Properties: map[string]interface{}{"resourceType": o.ResourceType},
		StartNode:  minimalUserNode(o.OwnerID), // Owner type unknown; default to User
		EndNode:    endNode,
	}
}

// RelationshipFromAppRoleAssignment creates a HAS_PERMISSION relationship
// for Microsoft Graph app role assignments.
func RelationshipFromAppRoleAssignment(ara types.AppRoleAssignment) *graph.Relationship {
	var startNode *graph.Node
	switch ara.PrincipalType {
	case "ServicePrincipal":
		startNode = minimalServicePrincipalNode(ara.PrincipalID)
	case "Group":
		startNode = minimalGroupNode(ara.PrincipalID)
	default:
		startNode = minimalUserNode(ara.PrincipalID)
	}
	return &graph.Relationship{
		Type: "HAS_PERMISSION",
		Properties: map[string]interface{}{
			"id":        ara.ID,
			"appRoleId": ara.AppRoleID,
			"source":    "Microsoft Graph App Role",
		},
		StartNode: startNode,
		EndNode:   minimalServicePrincipalNode(ara.ResourceID),
	}
}

// RelationshipFromOAuth2Grant creates a HAS_PERMISSION relationship
// for Microsoft Graph OAuth2 delegated permission grants.
func RelationshipFromOAuth2Grant(grant types.OAuth2PermissionGrant) *graph.Relationship {
	props := map[string]interface{}{
		"id":     grant.ID,
		"scope":  grant.Scope,
		"source": "Microsoft Graph OAuth2",
	}
	if grant.ConsentType != "" {
		props["consentType"] = grant.ConsentType
	}

	return &graph.Relationship{
		Type:       "HAS_PERMISSION",
		Properties: props,
		StartNode:  minimalServicePrincipalNode(grant.ClientID),
		EndNode:    minimalServicePrincipalNode(grant.ResourceID),
	}
}

// RelationshipFromRBACAssignment creates a HAS_PERMISSION relationship
// for Azure RBAC role assignments.
func RelationshipFromRBACAssignment(ra types.RoleAssignment) *graph.Relationship {
	props := map[string]interface{}{
		"id":               ra.ID,
		"roleDefinitionId": ra.RoleDefinitionID,
		"scope":            ra.Scope,
		"source":           "Azure RBAC",
	}
	if ra.PrincipalType != "" {
		props["principalType"] = ra.PrincipalType
	}
	if ra.Condition != "" {
		props["condition"] = ra.Condition
	}

	endNode := scopeNode(ra.Scope)

	return &graph.Relationship{
		Type:       "HAS_PERMISSION",
		Properties: props,
		StartNode:  principalNodeByAzureType(ra.PrincipalID, ra.PrincipalType),
		EndNode:    endNode,
	}
}

// RelationshipFromMgmtGroupHierarchy creates a CONTAINS relationship.
// StartNode: ManagementGroup node with ID = rel.ParentID
// EndNode: ManagementGroup or Subscription node with ID = rel.ChildID
func RelationshipFromMgmtGroupHierarchy(rel types.ManagementGroupRelationship) *graph.Relationship {
	var endNode *graph.Node
	if strings.EqualFold(rel.ChildType, "subscription") {
		endNode = NodeFromSubscription(rel.ChildID)
	} else {
		endNode = &graph.Node{
			Labels:     []string{"ManagementGroup", "Azure::Management::ManagementGroup"},
			Properties: map[string]interface{}{"id": rel.ChildID},
			UniqueKey:  []string{"id"},
		}
	}

	return &graph.Relationship{
		Type:       "CONTAINS",
		Properties: map[string]interface{}{"childType": rel.ChildType},
		StartNode: &graph.Node{
			Labels:     []string{"ManagementGroup", "Azure::Management::ManagementGroup"},
			Properties: map[string]interface{}{"id": rel.ParentID},
			UniqueKey:  []string{"id"},
		},
		EndNode: endNode,
	}
}

// RelationshipFromPIMAssignment creates a HAS_PERMISSION relationship for PIM role assignments.
// The assignmentType property distinguishes active vs eligible assignments.
func RelationshipFromPIMAssignment(pa types.PIMRoleAssignment) *graph.Relationship {
	props := map[string]interface{}{
		"id":             pa.ID,
		"scope":          pa.Scope,
		"assignmentType": pa.AssignmentType,
		"source":         "PIM",
	}
	if pa.StartDateTime != "" {
		props["startDateTime"] = pa.StartDateTime
	}
	if pa.EndDateTime != "" {
		props["endDateTime"] = pa.EndDateTime
	}

	return &graph.Relationship{
		Type:       "HAS_PERMISSION",
		Properties: props,
		StartNode:  minimalUserNode(pa.PrincipalID), // Principal type unknown; default to User
		EndNode:    minimalRoleDefinitionNode(pa.RoleDefinitionID),
	}
}

// ---------------------------------------------------------------------------
// Bulk transformers
// ---------------------------------------------------------------------------

// TransformEntraIDData converts EntraIDData into graph nodes and relationships.
func TransformEntraIDData(data *types.EntraIDData) ([]*graph.Node, []*graph.Relationship) {
	if data == nil {
		return nil, nil
	}

	var nodes []*graph.Node
	var rels []*graph.Relationship

	// Users
	data.Users.Range(func(_ string, u types.EntraUser) bool {
		nodes = append(nodes, NodeFromEntraUser(u))
		return true
	})

	// Groups
	data.Groups.Range(func(_ string, g types.EntraGroup) bool {
		nodes = append(nodes, NodeFromEntraGroup(g))
		return true
	})

	// Service Principals
	data.ServicePrincipals.Range(func(_ string, sp types.EntraServicePrincipal) bool {
		nodes = append(nodes, NodeFromEntraServicePrincipal(sp))
		return true
	})

	// Applications
	data.Applications.Range(func(_ string, app types.EntraApplication) bool {
		nodes = append(nodes, NodeFromEntraApplication(app))
		return true
	})

	// Devices
	for _, d := range data.Devices {
		nodes = append(nodes, NodeFromEntraDevice(d))
	}

	// Directory Roles
	for _, dr := range data.DirectoryRoles {
		nodes = append(nodes, NodeFromDirectoryRole(dr))
	}

	// Role Definitions
	for _, rd := range data.RoleDefinitions {
		nodes = append(nodes, NodeFromEntraRoleDefinition(rd))
	}

	// Group Memberships
	for _, gm := range data.GroupMemberships {
		rels = append(rels, RelationshipFromGroupMembership(gm))
	}

	// Directory Role Assignments — resolve principal types from collected entities
	groupIDs := make(map[string]bool)
	data.Groups.Range(func(_ string, g types.EntraGroup) bool {
		groupIDs[g.ObjectID] = true
		return true
	})
	spIDs := make(map[string]bool)
	data.ServicePrincipals.Range(func(_ string, sp types.EntraServicePrincipal) bool {
		spIDs[sp.ObjectID] = true
		return true
	})
	for _, dra := range data.DirectoryRoleAssignments {
		if dra.PrincipalType == "" {
			switch {
			case groupIDs[dra.PrincipalID]:
				dra.PrincipalType = "Group"
			case spIDs[dra.PrincipalID]:
				dra.PrincipalType = "ServicePrincipal"
			default:
				dra.PrincipalType = "User"
			}
		}
		rels = append(rels, RelationshipFromDirectoryRoleAssignment(dra))
	}

	// Ownership Relationships
	for _, o := range data.OwnershipRelationships {
		rels = append(rels, RelationshipFromOwnership(o))
	}

	// App Role Assignments
	for _, ara := range data.AppRoleAssignments {
		rels = append(rels, RelationshipFromAppRoleAssignment(ara))
	}

	// OAuth2 Permission Grants
	for _, grant := range data.OAuth2PermissionGrants {
		rels = append(rels, RelationshipFromOAuth2Grant(grant))
	}

	return nodes, rels
}

// TransformRBACData converts a slice of RBACData into nodes and relationships.
func TransformRBACData(data []*types.RBACData) ([]*graph.Node, []*graph.Relationship) {
	var nodes []*graph.Node
	var rels []*graph.Relationship

	for _, rbac := range data {
		if rbac == nil {
			continue
		}

		// Subscription node
		nodes = append(nodes, NodeFromSubscription(rbac.SubscriptionID))

		// RBAC Role Definitions
		rbac.Definitions.Range(func(_ string, rd types.RoleDefinition) bool {
			nodes = append(nodes, NodeFromRBACRoleDefinition(rd))
			return true
		})

		// RBAC Assignments
		for _, ra := range rbac.Assignments {
			rels = append(rels, RelationshipFromRBACAssignment(ra))
		}
	}

	return nodes, rels
}

// TransformPIMData converts PIMData into relationships.
func TransformPIMData(data *types.PIMData) []*graph.Relationship {
	if data == nil {
		return nil
	}

	var rels []*graph.Relationship

	for _, pa := range data.ActiveAssignments {
		rels = append(rels, RelationshipFromPIMAssignment(pa))
	}
	for _, pa := range data.EligibleAssignments {
		rels = append(rels, RelationshipFromPIMAssignment(pa))
	}

	return rels
}

// TransformManagementGroupData converts ManagementGroupData into nodes and relationships.
func TransformManagementGroupData(data *types.ManagementGroupData) ([]*graph.Node, []*graph.Relationship) {
	if data == nil {
		return nil, nil
	}

	var nodes []*graph.Node
	var rels []*graph.Relationship

	for _, mg := range data.Groups {
		nodes = append(nodes, NodeFromManagementGroup(mg))
	}
	for _, rel := range data.Relationships {
		rels = append(rels, RelationshipFromMgmtGroupHierarchy(rel))
	}

	return nodes, rels
}

// NodeFromManagedIdentity creates a graph node from an Azure managed identity.
// Labels: ["ManagedIdentity", "Principal", "Azure::ManagedIdentity"]
// UniqueKey: ["id"]
func NodeFromManagedIdentity(mi types.ManagedIdentity) *graph.Node {
	props := flattenStruct(mi)
	props["_type"] = "ManagedIdentity"
	props["_resourceType"] = "Azure::ManagedIdentity"

	return &graph.Node{
		Labels:     []string{"ManagedIdentity", "Principal", "Azure::ManagedIdentity"},
		Properties: props,
		UniqueKey:  []string{"id"},
	}
}

// NodeFromResourceWithIdentity creates a graph node from a resource with a managed identity.
// Labels: ["AzureResource", "Azure::Resource"]
// UniqueKey: ["id"]
func NodeFromResourceWithIdentity(att types.ResourceIdentityAttachment) *graph.Node {
	return &graph.Node{
		Labels: []string{"AzureResource", "Azure::Resource"},
		Properties: map[string]interface{}{
			"id":           att.ResourceID,
			"displayName":  att.ResourceName,
			"resourceType": att.ResourceType,
			"_type":        "AzureResource",
		},
		UniqueKey: []string{"id"},
	}
}

// RelationshipFromMIToServicePrincipal creates a CONTAINS relationship from a
// managed identity to its underlying service principal (linked by principalId).
func RelationshipFromMIToServicePrincipal(mi types.ManagedIdentity) *graph.Relationship {
	return &graph.Relationship{
		Type:       "CONTAINS",
		Properties: map[string]interface{}{"relationship": "identity"},
		StartNode: &graph.Node{
			Labels:     []string{"ManagedIdentity", "Principal", "Azure::ManagedIdentity"},
			Properties: map[string]interface{}{"id": mi.ID},
			UniqueKey:  []string{"id"},
		},
		EndNode: minimalServicePrincipalNode(mi.PrincipalID),
	}
}

// RelationshipFromResourceToMI creates a CONTAINS relationship from an Azure
// resource to its attached managed identity (system-assigned or user-assigned).
func RelationshipFromResourceToMI(resourceID, miID, identityType string) *graph.Relationship {
	return &graph.Relationship{
		Type: "CONTAINS",
		Properties: map[string]interface{}{
			"identityType": identityType,
		},
		StartNode: &graph.Node{
			Labels:     []string{"AzureResource", "Azure::Resource"},
			Properties: map[string]interface{}{"id": resourceID},
			UniqueKey:  []string{"id"},
		},
		EndNode: &graph.Node{
			Labels:     []string{"ManagedIdentity", "Principal", "Azure::ManagedIdentity"},
			Properties: map[string]interface{}{"id": miID},
			UniqueKey:  []string{"id"},
		},
	}
}

// TransformManagedIdentityData converts ManagedIdentityData into nodes and relationships.
func TransformManagedIdentityData(data *types.ManagedIdentityData) ([]*graph.Node, []*graph.Relationship) {
	if data == nil {
		return nil, nil
	}

	var nodes []*graph.Node
	var rels []*graph.Relationship

	// User-assigned managed identities
	for _, mi := range data.Identities {
		nodes = append(nodes, NodeFromManagedIdentity(mi))
		if mi.PrincipalID != "" {
			rels = append(rels, RelationshipFromMIToServicePrincipal(mi))
		}
	}

	// Resource identity attachments
	for _, att := range data.Attachments {
		nodes = append(nodes, NodeFromResourceWithIdentity(att))

		// System-assigned: create synthetic MI node + resource → MI relationship
		if att.PrincipalID != "" && strings.Contains(strings.ToLower(att.IdentityType), "systemassigned") {
			syntheticMIID := "/virtual/managedidentity/system/" + att.PrincipalID
			syntheticMI := &graph.Node{
				Labels: []string{"ManagedIdentity", "Principal", "Azure::ManagedIdentity"},
				Properties: map[string]interface{}{
					"id":          syntheticMIID,
					"displayName": att.ResourceName + " (System-Assigned)",
					"principalId": att.PrincipalID,
					"_type":       "ManagedIdentity",
					"_synthetic":  true,
				},
				UniqueKey: []string{"id"},
			}
			nodes = append(nodes, syntheticMI)
			rels = append(rels, RelationshipFromResourceToMI(att.ResourceID, syntheticMIID, "SystemAssigned"))

			// MI → SP link
			rels = append(rels, &graph.Relationship{
				Type:       "CONTAINS",
				Properties: map[string]interface{}{"relationship": "identity"},
				StartNode: &graph.Node{
					Labels:     []string{"ManagedIdentity", "Principal", "Azure::ManagedIdentity"},
					Properties: map[string]interface{}{"id": syntheticMIID},
					UniqueKey:  []string{"id"},
				},
				EndNode: minimalServicePrincipalNode(att.PrincipalID),
			})
		}

		// User-assigned: resource → MI relationships
		for _, uaID := range att.UserAssignedIDs {
			rels = append(rels, RelationshipFromResourceToMI(att.ResourceID, uaID, "UserAssigned"))
		}
	}

	return nodes, rels
}

// TransformAll converts consolidated Azure IAM data into nodes and relationships.
func TransformAll(data *types.AzureIAMConsolidated) ([]*graph.Node, []*graph.Relationship) {
	if data == nil {
		return nil, nil
	}

	var allNodes []*graph.Node
	var allRels []*graph.Relationship

	// Entra ID
	if nodes, rels := TransformEntraIDData(data.EntraID); nodes != nil || rels != nil {
		allNodes = append(allNodes, nodes...)
		allRels = append(allRels, rels...)
	}

	// RBAC
	if nodes, rels := TransformRBACData(data.RBAC); nodes != nil || rels != nil {
		allNodes = append(allNodes, nodes...)
		allRels = append(allRels, rels...)
	}

	// PIM
	if rels := TransformPIMData(data.PIM); rels != nil {
		allRels = append(allRels, rels...)
	}

	// Management Groups
	if nodes, rels := TransformManagementGroupData(data.ManagementGroups); nodes != nil || rels != nil {
		allNodes = append(allNodes, nodes...)
		allRels = append(allRels, rels...)
	}

	// Managed Identities
	if nodes, rels := TransformManagedIdentityData(data.ManagedIdentities); nodes != nil || rels != nil {
		allNodes = append(allNodes, nodes...)
		allRels = append(allRels, rels...)
	}

	return allNodes, allRels
}

// ---------------------------------------------------------------------------
// Minimal node helpers (for relationship endpoints)
//
// IMPORTANT: Minimal nodes MUST use the SAME label set as the corresponding
// full node constructor. Neo4j MERGE matches on ALL labels + unique key.
// If labels differ, MERGE creates duplicate nodes instead of reusing.
// ---------------------------------------------------------------------------

// minimalUserNode creates a User node with the same labels as NodeFromEntraUser.
func minimalUserNode(id string) *graph.Node {
	return &graph.Node{
		Labels:     []string{"User", "Principal", "Azure::EntraID::User"},
		Properties: map[string]interface{}{"id": id},
		UniqueKey:  []string{"id"},
	}
}

// minimalGroupNode creates a Group node with the same labels as NodeFromEntraGroup.
func minimalGroupNode(id string) *graph.Node {
	return &graph.Node{
		Labels:     []string{"Group", "Azure::EntraID::Group"},
		Properties: map[string]interface{}{"id": id},
		UniqueKey:  []string{"id"},
	}
}

// minimalServicePrincipalNode creates an SP node with the same labels as NodeFromEntraServicePrincipal.
func minimalServicePrincipalNode(id string) *graph.Node {
	return &graph.Node{
		Labels:     []string{"ServicePrincipal", "Principal", "Azure::EntraID::ServicePrincipal"},
		Properties: map[string]interface{}{"id": id},
		UniqueKey:  []string{"id"},
	}
}

// minimalRoleDefinitionNode creates a RoleDefinition node with the same labels as NodeFromEntraRoleDefinition.
func minimalRoleDefinitionNode(id string) *graph.Node {
	return &graph.Node{
		Labels:     []string{"RoleDefinition", "Azure::EntraID::RoleDefinition"},
		Properties: map[string]interface{}{"id": id},
		UniqueKey:  []string{"id"},
	}
}

// principalNodeByType creates a minimal principal node with the correct labels
// based on the OData type string from Microsoft Graph (e.g., "#microsoft.graph.user").
// Falls back to User labels for unknown types (most common principal type).
func principalNodeByType(id string, odataType string) *graph.Node {
	lower := strings.ToLower(odataType)
	switch {
	case strings.Contains(lower, "group"):
		return minimalGroupNode(id)
	case strings.Contains(lower, "serviceprincipal"):
		return minimalServicePrincipalNode(id)
	default:
		if odataType != "" && !strings.Contains(lower, "user") {
			slog.Debug("unknown OData principal type, defaulting to User", "id", id, "odataType", odataType)
		}
		return minimalUserNode(id)
	}
}

// principalNodeByAzureType creates a minimal principal node based on the Azure
// ARM principalType string (e.g., "User", "Group", "ServicePrincipal").
func principalNodeByAzureType(id string, principalType string) *graph.Node {
	switch strings.ToLower(principalType) {
	case "group":
		return minimalGroupNode(id)
	case "serviceprincipal":
		return minimalServicePrincipalNode(id)
	default:
		if principalType != "" && !strings.EqualFold(principalType, "user") {
			slog.Debug("unknown ARM principal type, defaulting to User", "id", id, "principalType", principalType)
		}
		return minimalUserNode(id)
	}
}

// scopeNode creates a node for an RBAC scope. If the scope looks like a subscription
// (e.g., "/subscriptions/<id>"), it returns a Subscription node; otherwise a generic Resource node.
func scopeNode(scope string) *graph.Node {
	parts := strings.Split(scope, "/")
	// /subscriptions/<subID> or /subscriptions/<subID>/...
	if len(parts) >= 3 && strings.EqualFold(parts[1], "subscriptions") {
		return NodeFromSubscription(parts[2])
	}

	return &graph.Node{
		Labels:     []string{"Resource"},
		Properties: map[string]interface{}{"id": scope},
		UniqueKey:  []string{"id"},
	}
}

// ---------------------------------------------------------------------------
// Neo4j-safe property utilities (copied from AWS transformer; unexported there)
// ---------------------------------------------------------------------------

// flattenStruct converts a Go struct to map[string]interface{} with only Neo4j-compatible values.
func flattenStruct(obj interface{}) map[string]interface{} {
	data, err := json.Marshal(obj)
	if err != nil {
		return map[string]interface{}{}
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return map[string]interface{}{}
	}

	result := make(map[string]interface{}, len(raw))
	for k, v := range raw {
		if neo4jSafe := toNeo4jProperty(v); neo4jSafe != nil {
			result[k] = neo4jSafe
		}
	}
	return result
}

// toNeo4jProperty converts a value to a Neo4j-compatible property value.
func toNeo4jProperty(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return val
	case bool:
		return val
	case []interface{}:
		return toNeo4jArray(val)
	default:
		data, err := json.Marshal(val)
		if err != nil {
			return nil
		}
		s := string(data)
		if s == "{}" || s == "null" {
			return nil
		}
		return s
	}
}

// toNeo4jArray converts an array to a Neo4j-compatible array.
func toNeo4jArray(arr []interface{}) interface{} {
	if len(arr) == 0 {
		return nil
	}
	allStrings := true
	for _, elem := range arr {
		if _, ok := elem.(string); !ok {
			allStrings = false
			break
		}
	}
	if allStrings {
		strs := make([]string, len(arr))
		for i, elem := range arr {
			strs[i] = elem.(string)
		}
		return strs
	}
	allNumbers := true
	for _, elem := range arr {
		if _, ok := elem.(float64); !ok {
			allNumbers = false
			break
		}
	}
	if allNumbers {
		return arr
	}
	data, err := json.Marshal(arr)
	if err != nil {
		return nil
	}
	s := string(data)
	if s == "[]" || s == "null" {
		return nil
	}
	return s
}
