package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildEntityCounts_NilConsolidated(t *testing.T) {
	// Should not panic on nil input.
	assert.NotPanics(t, func() {
		counts := buildEntityCounts(nil)
		assert.NotNil(t, counts)
		assert.Empty(t, counts)
	})
}

func TestBuildEntityCounts_Populated(t *testing.T) {
	entra := types.NewEntraIDData(
		"tenant-1",
		[]types.EntraUser{{ObjectID: "u1"}, {ObjectID: "u2"}},
		[]types.EntraGroup{{ObjectID: "g1"}},
		[]types.EntraServicePrincipal{{ObjectID: "sp1"}, {ObjectID: "sp2"}, {ObjectID: "sp3"}},
		[]types.EntraApplication{{ObjectID: "app1"}},
	)
	entra.Devices = []types.EntraDevice{{ObjectID: "d1"}}
	entra.DirectoryRoles = []types.DirectoryRole{{ObjectID: "dr1"}, {ObjectID: "dr2"}}
	entra.GroupMemberships = []types.GroupMembership{{GroupID: "g1", MemberID: "u1"}}
	entra.OwnershipRelationships = []types.OwnershipRelationship{
		{OwnerID: "u1", ResourceID: "app1"},
		{OwnerID: "u2", ResourceID: "sp1"},
	}

	pim := &types.PIMData{
		ActiveAssignments:   []types.PIMRoleAssignment{{ID: "pa1"}, {ID: "pa2"}},
		EligibleAssignments: []types.PIMRoleAssignment{{ID: "pe1"}},
	}

	rbac := []*types.RBACData{
		{SubscriptionID: "sub-1", Definitions: store.NewMap[types.RoleDefinition]()},
		{SubscriptionID: "sub-2", Definitions: store.NewMap[types.RoleDefinition]()},
	}

	mgmt := &types.ManagementGroupData{
		Groups:        []types.ManagementGroup{{ID: "mg1"}},
		Relationships: []types.ManagementGroupRelationship{{ParentID: "mg1", ChildID: "sub-1"}},
	}

	mi := &types.ManagedIdentityData{
		Identities:  []types.ManagedIdentity{{ID: "mi1"}, {ID: "mi2"}, {ID: "mi3"}},
		Attachments: []types.ResourceIdentityAttachment{{ResourceID: "r1"}},
	}

	consolidated := &types.AzureIAMConsolidated{
		EntraID:           entra,
		PIM:               pim,
		RBAC:              rbac,
		ManagementGroups:  mgmt,
		ManagedIdentities: mi,
	}

	counts := buildEntityCounts(consolidated)

	assert.Equal(t, 2, counts["users"])
	assert.Equal(t, 1, counts["groups"])
	assert.Equal(t, 3, counts["servicePrincipals"])
	assert.Equal(t, 1, counts["applications"])
	assert.Equal(t, 1, counts["devices"])
	assert.Equal(t, 2, counts["directoryRoles"])
	assert.Equal(t, 1, counts["groupMemberships"])
	assert.Equal(t, 2, counts["ownershipRelationships"])
	assert.Equal(t, 2, counts["pimActiveAssignments"])
	assert.Equal(t, 1, counts["pimEligibleAssignments"])
	assert.Equal(t, 2, counts["rbacSubscriptions"])
	assert.Equal(t, 1, counts["managementGroups"])
	assert.Equal(t, 1, counts["mgmtGroupRelationships"])
	assert.Equal(t, 3, counts["managedIdentities"])
	assert.Equal(t, 1, counts["identityAttachments"])
}

func TestBuildEntityCounts_PartialData_NilRBAC(t *testing.T) {
	// Only EntraID is populated; RBAC, PIM, etc. are nil.
	entra := types.NewEntraIDData(
		"tenant-1",
		[]types.EntraUser{{ObjectID: "u1"}},
		nil, nil, nil,
	)

	consolidated := &types.AzureIAMConsolidated{
		EntraID: entra,
		// PIM, RBAC, ManagementGroups, ManagedIdentities all nil
	}

	counts := buildEntityCounts(consolidated)

	assert.Equal(t, 1, counts["users"])
	assert.Equal(t, 0, counts["groups"])
	assert.Equal(t, 0, counts["servicePrincipals"])
	assert.Equal(t, 0, counts["applications"])

	// Keys from nil sub-collectors should not be present.
	_, hasPIM := counts["pimActiveAssignments"]
	assert.False(t, hasPIM, "PIM keys should not exist when PIM is nil")
	_, hasRBAC := counts["rbacSubscriptions"]
	assert.False(t, hasRBAC, "RBAC keys should not exist when RBAC is nil")
}

func TestBuildEntityCounts_PartialData_NilEntraID(t *testing.T) {
	// Only PIM is populated; EntraID is nil.
	pim := &types.PIMData{
		ActiveAssignments:   []types.PIMRoleAssignment{{ID: "pa1"}},
		EligibleAssignments: nil,
	}

	consolidated := &types.AzureIAMConsolidated{
		PIM: pim,
		// EntraID, RBAC, ManagementGroups, ManagedIdentities all nil
	}

	counts := buildEntityCounts(consolidated)

	_, hasUsers := counts["users"]
	assert.False(t, hasUsers, "Entra keys should not exist when EntraID is nil")
	assert.Equal(t, 1, counts["pimActiveAssignments"])
	assert.Equal(t, 0, counts["pimEligibleAssignments"])
}
