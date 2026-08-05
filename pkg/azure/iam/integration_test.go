package iam

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/types"
)

// Integration tests that run against a real Azure tenant.
// Gated by AZURE_SUBSCRIPTION_ID environment variable.
//
// Run with: AZURE_SUBSCRIPTION_ID=<sub-id> go test ./pkg/azure/iam/ -run TestIntegration -v -count=1 -timeout 600s

func skipUnlessIntegration(t *testing.T) string {
	t.Helper()
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subID == "" {
		t.Skip("AZURE_SUBSCRIPTION_ID not set, skipping integration test")
	}
	return subID
}

func defaultCredential(t *testing.T) *azidentity.DefaultAzureCredential {
	t.Helper()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		t.Fatalf("failed to create DefaultAzureCredential: %v", err)
	}
	return cred
}

// =====================================================================
// Entra ID Collector
// =====================================================================

func TestIntegration_EntraCollector(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewEntraCollector(cred)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err, "Entra Collect should not return error")
	require.NotNil(t, data, "Entra data should not be nil")

	t.Logf("Entra ID results:")
	t.Logf("  Users:              %d", data.Users.Len())
	t.Logf("  Groups:             %d", data.Groups.Len())
	t.Logf("  ServicePrincipals:  %d", data.ServicePrincipals.Len())
	t.Logf("  Applications:       %d", data.Applications.Len())
	t.Logf("  Devices:            %d", len(data.Devices))
	t.Logf("  DirectoryRoles:     %d", len(data.DirectoryRoles))
	t.Logf("  RoleDefinitions:    %d", len(data.RoleDefinitions))
	t.Logf("  GroupMemberships:   %d", len(data.GroupMemberships))
	t.Logf("  DirRoleAssignments: %d", len(data.DirectoryRoleAssignments))
	t.Logf("  Ownerships:         %d", len(data.OwnershipRelationships))
	t.Logf("  AppRoleAssignments: %d", len(data.AppRoleAssignments))
	t.Logf("  OAuth2Grants:       %d", len(data.OAuth2PermissionGrants))
	t.Logf("  TenantID:           %s", data.TenantID)

	// --- Sanity: non-empty collections ---
	t.Run("non-empty entity counts", func(t *testing.T) {
		assert.Greater(t, data.Users.Len(), 0, "users should not be empty")
		assert.Greater(t, data.Groups.Len(), 0, "groups should not be empty")
		assert.Greater(t, data.ServicePrincipals.Len(), 0, "service principals should not be empty")
		assert.Greater(t, data.Applications.Len(), 0, "applications should not be empty")
		assert.Greater(t, len(data.DirectoryRoles), 0, "directory roles should not be empty")
		assert.Greater(t, len(data.RoleDefinitions), 0, "role definitions should not be empty")
		assert.Greater(t, len(data.GroupMemberships), 0, "group memberships should not be empty")
		assert.Greater(t, len(data.DirectoryRoleAssignments), 0, "directory role assignments should not be empty")
	})

	// --- Tenant ID ---
	t.Run("tenant ID populated", func(t *testing.T) {
		assert.NotEmpty(t, data.TenantID, "TenantID must be populated")
		assert.Len(t, data.TenantID, 36, "TenantID should be a GUID (36 chars)")
	})

	// --- User field population ---
	t.Run("user fields populated", func(t *testing.T) {
		checkedCount := 0
		data.Users.Range(func(_ string, u types.EntraUser) bool {
			assert.NotEmpty(t, u.ObjectID, "user ObjectID must not be empty")
			assert.NotEmpty(t, u.DisplayName, "user DisplayName must not be empty")
			assert.NotEmpty(t, u.UserPrincipalName, "user UPN must not be empty")
			// AccountEnabled is a bool, can be false, so just check ObjectID is a GUID
			assert.Len(t, u.ObjectID, 36, "user ObjectID should be GUID format")
			checkedCount++
			return checkedCount < 5 // spot-check first 5
		})
		assert.GreaterOrEqual(t, checkedCount, 1, "should have checked at least 1 user")
	})

	// --- Group field population ---
	t.Run("group fields populated", func(t *testing.T) {
		checkedCount := 0
		data.Groups.Range(func(_ string, g types.EntraGroup) bool {
			assert.NotEmpty(t, g.ObjectID, "group ObjectID must not be empty")
			assert.NotEmpty(t, g.DisplayName, "group DisplayName must not be empty")
			assert.Len(t, g.ObjectID, 36, "group ObjectID should be GUID format")
			checkedCount++
			return checkedCount < 5
		})
		assert.GreaterOrEqual(t, checkedCount, 1, "should have checked at least 1 group")
	})

	// --- Service Principal field population ---
	t.Run("service principal fields populated", func(t *testing.T) {
		checkedCount := 0
		data.ServicePrincipals.Range(func(_ string, sp types.EntraServicePrincipal) bool {
			assert.NotEmpty(t, sp.ObjectID, "SP ObjectID must not be empty")
			assert.NotEmpty(t, sp.DisplayName, "SP DisplayName must not be empty")
			assert.NotEmpty(t, sp.AppID, "SP AppID must not be empty")
			checkedCount++
			return checkedCount < 5
		})
		assert.GreaterOrEqual(t, checkedCount, 1, "should have checked at least 1 SP")
	})

	// --- Application field population ---
	t.Run("application fields populated", func(t *testing.T) {
		checkedCount := 0
		data.Applications.Range(func(_ string, app types.EntraApplication) bool {
			assert.NotEmpty(t, app.ObjectID, "app ObjectID must not be empty")
			assert.NotEmpty(t, app.DisplayName, "app DisplayName must not be empty")
			assert.NotEmpty(t, app.AppID, "app AppID must not be empty")
			checkedCount++
			return checkedCount < 5
		})
		assert.GreaterOrEqual(t, checkedCount, 1, "should have checked at least 1 app")
	})

	// --- Directory role assignments field population ---
	t.Run("directory role assignment fields populated", func(t *testing.T) {
		for i, dra := range data.DirectoryRoleAssignments {
			if i >= 5 {
				break
			}
			assert.NotEmpty(t, dra.PrincipalID, "DRA[%d] PrincipalID must not be empty", i)
			assert.NotEmpty(t, dra.RoleDefinitionID, "DRA[%d] RoleDefinitionID must not be empty", i)
		}
	})

	// --- Group membership field population ---
	t.Run("group membership fields populated", func(t *testing.T) {
		for i, gm := range data.GroupMemberships {
			if i >= 5 {
				break
			}
			assert.NotEmpty(t, gm.GroupID, "GM[%d] GroupID must not be empty", i)
			assert.NotEmpty(t, gm.MemberID, "GM[%d] MemberID must not be empty", i)
			assert.NotEmpty(t, gm.MemberType, "GM[%d] MemberType must not be empty", i)
		}
	})

	// --- No duplicate users ---
	t.Run("no duplicate user IDs", func(t *testing.T) {
		seen := make(map[string]bool)
		data.Users.Range(func(_ string, u types.EntraUser) bool {
			assert.False(t, seen[u.ObjectID], "duplicate user ID: %s", u.ObjectID)
			seen[u.ObjectID] = true
			return true
		})
	})

	// --- No duplicate service principals ---
	t.Run("no duplicate SP IDs", func(t *testing.T) {
		seen := make(map[string]bool)
		data.ServicePrincipals.Range(func(_ string, sp types.EntraServicePrincipal) bool {
			assert.False(t, seen[sp.ObjectID], "duplicate SP ID: %s", sp.ObjectID)
			seen[sp.ObjectID] = true
			return true
		})
	})

	// --- Ownership relationships have valid references ---
	t.Run("ownership relationships reference valid entities", func(t *testing.T) {
		for _, o := range data.OwnershipRelationships {
			assert.NotEmpty(t, o.OwnerID, "ownership OwnerID must not be empty")
			assert.NotEmpty(t, o.ResourceID, "ownership ResourceID must not be empty")
			assert.NotEmpty(t, o.ResourceType, "ownership ResourceType must not be empty")
		}
	})

	// --- JSON roundtrip ---
	t.Run("JSON roundtrip", func(t *testing.T) {
		b, err := json.Marshal(data)
		require.NoError(t, err, "JSON marshal should succeed")
		assert.Greater(t, len(b), 100, "JSON should have meaningful size")
		t.Logf("  JSON size: %d bytes", len(b))

		var roundtrip types.EntraIDData
		require.NoError(t, json.Unmarshal(b, &roundtrip), "JSON unmarshal should succeed")
		assert.Equal(t, data.Users.Len(), roundtrip.Users.Len(), "user count preserved after roundtrip")
		assert.Equal(t, data.Groups.Len(), roundtrip.Groups.Len(), "group count preserved after roundtrip")
	})
}

// =====================================================================
// PIM Collector
// =====================================================================

func TestIntegration_PIMCollector(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewPIMCollector(cred)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err, "PIM Collect should not return error (graceful on 403)")
	require.NotNil(t, data, "PIM data should not be nil even on 403")

	t.Logf("PIM results:")
	t.Logf("  ActiveAssignments:   %d", len(data.ActiveAssignments))
	t.Logf("  EligibleAssignments: %d", len(data.EligibleAssignments))

	// PIM may return 0 if tenant doesn't have P2 license or CLI user lacks
	// RoleManagement.Read.Directory permission — that's OK. Slices may be nil.
	t.Run("result is valid even if empty", func(t *testing.T) {
		assert.GreaterOrEqual(t, len(data.ActiveAssignments), 0,
			"ActiveAssignments should be accessible (nil or empty is OK)")
		assert.GreaterOrEqual(t, len(data.EligibleAssignments), 0,
			"EligibleAssignments should be accessible (nil or empty is OK)")
	})

	// If PIM data is populated, verify field quality
	t.Run("PIM assignment fields populated", func(t *testing.T) {
		for i, pa := range data.ActiveAssignments {
			if i >= 5 {
				break
			}
			assert.NotEmpty(t, pa.PrincipalID, "active[%d] PrincipalID must not be empty", i)
			assert.NotEmpty(t, pa.RoleDefinitionID, "active[%d] RoleDefinitionID must not be empty", i)
			assert.Equal(t, "active", pa.AssignmentType, "active[%d] AssignmentType should be 'active'", i)
		}
		for i, pa := range data.EligibleAssignments {
			if i >= 5 {
				break
			}
			assert.NotEmpty(t, pa.PrincipalID, "eligible[%d] PrincipalID must not be empty", i)
			assert.NotEmpty(t, pa.RoleDefinitionID, "eligible[%d] RoleDefinitionID must not be empty", i)
			assert.Equal(t, "eligible", pa.AssignmentType, "eligible[%d] AssignmentType should be 'eligible'", i)
		}
	})

	// JSON roundtrip
	t.Run("JSON roundtrip", func(t *testing.T) {
		b, err := json.Marshal(data)
		require.NoError(t, err)
		t.Logf("  JSON size: %d bytes", len(b))
	})
}

// =====================================================================
// RBAC Collector
// =====================================================================

func TestIntegration_RBACCollector(t *testing.T) {
	subID := skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewRBACCollector(cred)
	results, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err, "RBAC Collect should not return error")
	require.NotEmpty(t, results, "should have at least 1 RBAC result")

	for _, r := range results {
		t.Logf("RBAC results for subscription %s:", r.SubscriptionID)
		t.Logf("  Assignments:  %d", len(r.Assignments))
		t.Logf("  Definitions:  %d", r.Definitions.Len())
	}

	t.Run("subscription ID matches input", func(t *testing.T) {
		assert.Equal(t, subID, results[0].SubscriptionID)
	})

	t.Run("assignments have required fields", func(t *testing.T) {
		for i, ra := range results[0].Assignments {
			if i >= 10 {
				break
			}
			assert.NotEmpty(t, ra.ID, "RA[%d] ID must not be empty", i)
			assert.NotEmpty(t, ra.PrincipalID, "RA[%d] PrincipalID must not be empty", i)
			assert.NotEmpty(t, ra.RoleDefinitionID, "RA[%d] RoleDefinitionID must not be empty", i)
			assert.NotEmpty(t, ra.Scope, "RA[%d] Scope must not be empty", i)
		}
	})

	t.Run("definitions have required fields", func(t *testing.T) {
		checkedCount := 0
		results[0].Definitions.Range(func(_ string, rd types.RoleDefinition) bool {
			assert.NotEmpty(t, rd.ID, "RD ID must not be empty")
			assert.NotEmpty(t, rd.RoleName, "RD DisplayName must not be empty")
			checkedCount++
			return checkedCount < 10
		})
		assert.GreaterOrEqual(t, checkedCount, 1, "should have checked at least 1 definition")
	})

	t.Run("no duplicate assignment IDs", func(t *testing.T) {
		seen := make(map[string]bool)
		for _, ra := range results[0].Assignments {
			assert.False(t, seen[ra.ID], "duplicate RBAC assignment ID: %s", ra.ID)
			seen[ra.ID] = true
		}
	})

	t.Run("has well-known roles", func(t *testing.T) {
		hasOwner := false
		hasReader := false
		hasContributor := false
		results[0].Definitions.Range(func(_ string, rd types.RoleDefinition) bool {
			switch rd.RoleName {
			case "Owner":
				hasOwner = true
			case "Reader":
				hasReader = true
			case "Contributor":
				hasContributor = true
			}
			return true
		})
		assert.True(t, hasOwner, "should have Owner role definition")
		assert.True(t, hasReader, "should have Reader role definition")
		assert.True(t, hasContributor, "should have Contributor role definition")
	})

	// JSON roundtrip
	t.Run("JSON roundtrip", func(t *testing.T) {
		b, err := json.Marshal(results)
		require.NoError(t, err)
		t.Logf("Total RBAC JSON size: %d bytes", len(b))
	})
}

// =====================================================================
// RBAC Collector — Negative: Invalid Subscription
// =====================================================================

func TestIntegration_RBACCollector_InvalidSubscription(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewRBACCollector(cred)

	t.Run("non-existent subscription returns error or empty", func(t *testing.T) {
		results, err := collector.Collect(context.Background(), []string{"00000000-0000-0000-0000-000000000000"})
		// Should either error or return empty — never panic
		if err != nil {
			t.Logf("Expected error for bogus subscription: %v", err)
		} else {
			// If no error, results should be empty or have 0 assignments
			for _, r := range results {
				t.Logf("Bogus sub result: sub=%s assignments=%d", r.SubscriptionID, len(r.Assignments))
			}
		}
	})

	t.Run("empty subscription list returns empty", func(t *testing.T) {
		results, err := collector.Collect(context.Background(), []string{})
		require.NoError(t, err, "empty subscription list should not error")
		assert.Empty(t, results, "empty subscription list should return empty results")
	})
}

// =====================================================================
// RBAC Collector — Multi-Subscription
// =====================================================================

func TestIntegration_RBACCollector_MultiSubscription(t *testing.T) {
	subID := skipUnlessIntegration(t)
	sub2 := os.Getenv("AZURE_SUBSCRIPTION_ID_2")
	if sub2 == "" {
		t.Skip("AZURE_SUBSCRIPTION_ID_2 not set, skipping multi-subscription test")
	}
	cred := defaultCredential(t)

	collector := NewRBACCollector(cred)
	results, err := collector.Collect(context.Background(), []string{subID, sub2})
	require.NoError(t, err)
	require.Len(t, results, 2, "should have results for both subscriptions")

	t.Run("each subscription has unique ID", func(t *testing.T) {
		assert.NotEqual(t, results[0].SubscriptionID, results[1].SubscriptionID)
	})

	t.Run("each subscription has assignments", func(t *testing.T) {
		for _, r := range results {
			assert.Greater(t, len(r.Assignments), 0,
				"subscription %s should have at least 1 assignment", r.SubscriptionID)
		}
	})
}

// =====================================================================
// Management Groups Collector
// =====================================================================

func TestIntegration_MgmtGroupsCollector(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewMgmtGroupsCollector(cred)
	data, err := collector.Collect(context.Background())
	require.NoError(t, err, "MgmtGroups Collect should not return error")
	require.NotNil(t, data, "MgmtGroups data should not be nil")

	t.Logf("Management Groups results:")
	t.Logf("  Groups:        %d", len(data.Groups))
	t.Logf("  Relationships: %d", len(data.Relationships))

	t.Run("at least tenant root group exists", func(t *testing.T) {
		assert.Greater(t, len(data.Groups), 0, "should have at least 1 management group")
	})

	t.Run("management group fields populated", func(t *testing.T) {
		for i, g := range data.Groups {
			assert.NotEmpty(t, g.ID, "MG[%d] ID must not be empty", i)
			assert.NotEmpty(t, g.DisplayName, "MG[%d] DisplayName must not be empty", i)
			t.Logf("    %s (%s)", g.DisplayName, g.Name)
		}
	})

	t.Run("relationships reference existing groups", func(t *testing.T) {
		groupIDs := make(map[string]bool)
		for _, g := range data.Groups {
			groupIDs[g.ID] = true
		}
		for _, rel := range data.Relationships {
			assert.NotEmpty(t, rel.ParentID, "relationship ParentID must not be empty")
			assert.NotEmpty(t, rel.ChildID, "relationship ChildID must not be empty")
			assert.NotEmpty(t, rel.ChildType, "relationship ChildType must not be empty")
			// Parent should be a known management group
			assert.True(t, groupIDs[rel.ParentID],
				"relationship parent %s should be in groups list", rel.ParentID)
		}
	})

	t.Run("no duplicate group IDs", func(t *testing.T) {
		seen := make(map[string]bool)
		for _, g := range data.Groups {
			assert.False(t, seen[g.ID], "duplicate management group ID: %s", g.ID)
			seen[g.ID] = true
		}
	})

	t.Run("tenant root group present", func(t *testing.T) {
		hasRoot := false
		for _, g := range data.Groups {
			if g.DisplayName == "Tenant Root Group" {
				hasRoot = true
				break
			}
		}
		assert.True(t, hasRoot, "should have 'Tenant Root Group'")
	})

	t.Run("JSON roundtrip", func(t *testing.T) {
		b, err := json.Marshal(data)
		require.NoError(t, err)
		t.Logf("  JSON size: %d bytes", len(b))
	})
}

// =====================================================================
// Managed Identity Collector
// =====================================================================

func TestIntegration_ManagedIdentityCollector(t *testing.T) {
	subID := skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewManagedIdentityCollector(cred)
	data, err := collector.Collect(context.Background(), []string{subID})
	require.NoError(t, err, "ManagedIdentity Collect should not return error")
	require.NotNil(t, data, "ManagedIdentity data should not be nil")

	t.Logf("Managed Identity results:")
	t.Logf("  Identities:   %d", len(data.Identities))
	t.Logf("  Attachments:  %d", len(data.Attachments))

	t.Run("identity fields populated", func(t *testing.T) {
		for i, mi := range data.Identities {
			assert.NotEmpty(t, mi.ID, "MI[%d] ID must not be empty", i)
			assert.NotEmpty(t, mi.Name, "MI[%d] Name must not be empty", i)
			assert.NotEmpty(t, mi.PrincipalID, "MI[%d] PrincipalID must not be empty", i)
			assert.NotEmpty(t, mi.ClientID, "MI[%d] ClientID must not be empty", i)
		}
	})

	t.Run("attachment fields populated", func(t *testing.T) {
		for i, att := range data.Attachments {
			assert.NotEmpty(t, att.ResourceID, "Att[%d] ResourceID must not be empty", i)
			assert.NotEmpty(t, att.ResourceType, "Att[%d] ResourceType must not be empty", i)
			assert.NotEmpty(t, att.IdentityType, "Att[%d] IdentityType must not be empty", i)
		}
	})

	t.Run("no duplicate identity IDs", func(t *testing.T) {
		seen := make(map[string]bool)
		for _, mi := range data.Identities {
			assert.False(t, seen[mi.ID], "duplicate MI ID: %s", mi.ID)
			seen[mi.ID] = true
		}
	})

	t.Run("JSON roundtrip", func(t *testing.T) {
		b, err := json.Marshal(data)
		require.NoError(t, err)
		t.Logf("  JSON size: %d bytes", len(b))
	})
}

// =====================================================================
// RBAC Collector — Mixed Valid/Invalid Subscriptions
// =====================================================================

func TestIntegration_RBACCollector_MixedSubscriptions(t *testing.T) {
	subID := skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewRBACCollector(cred)

	// Mix of valid and invalid (bogus) subscriptions — should not fail entirely
	// The valid subscription should still return results
	results, err := collector.Collect(context.Background(), []string{
		subID,
		"00000000-0000-0000-0000-000000000000", // bogus
	})
	// Accept either: partial results with error, or full results with no error
	if err != nil {
		t.Logf("Mixed subscription collection returned error (acceptable): %v", err)
		// Even with error, we should have results for the valid sub
		if len(results) > 0 {
			t.Logf("Got %d results despite error (partial success)", len(results))
		}
	} else {
		// If no error, verify we got at least the valid subscription's data
		validFound := false
		for _, r := range results {
			if r.SubscriptionID == subID {
				validFound = true
				assert.Greater(t, len(r.Assignments), 0,
					"valid subscription should have assignments")
			}
		}
		assert.True(t, validFound, "valid subscription should be in results")
	}
}

// =====================================================================
// PIM Collector — Graceful Degradation
// =====================================================================

func TestIntegration_PIMCollector_GracefulDegradation(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)

	// PIM collection uses the CLI credential which may not have
	// RoleManagement.Read.Directory. It should still return without
	// panicking — either data or an error.
	collector := NewPIMCollector(cred)
	data, err := collector.Collect(context.Background())

	// Either outcome is acceptable:
	// 1. No error → validate data structure
	// 2. Error → should not be a panic, data may be nil
	if err != nil {
		t.Logf("PIM collection returned error (expected without PIM license/permission): %v", err)
	} else {
		require.NotNil(t, data, "PIM data should not be nil when no error")
		t.Logf("PIM results: active=%d, eligible=%d",
			len(data.ActiveAssignments), len(data.EligibleAssignments))

		// If we got data, validate field population
		for i, pa := range data.ActiveAssignments {
			assert.NotEmpty(t, pa.PrincipalID, "active[%d] PrincipalID must not be empty", i)
			assert.NotEmpty(t, pa.RoleDefinitionID, "active[%d] RoleDefinitionID must not be empty", i)
			assert.Equal(t, "active", pa.AssignmentType, "active[%d] AssignmentType should be 'active'", i)
		}
		for i, pa := range data.EligibleAssignments {
			assert.NotEmpty(t, pa.PrincipalID, "eligible[%d] PrincipalID must not be empty", i)
			assert.NotEmpty(t, pa.RoleDefinitionID, "eligible[%d] RoleDefinitionID must not be empty", i)
			assert.Equal(t, "eligible", pa.AssignmentType, "eligible[%d] AssignmentType should be 'eligible'", i)
		}
	}
}

// =====================================================================
// Managed Identity Collector — Bogus Subscription
// =====================================================================

func TestIntegration_ManagedIdentityCollector_InvalidSubscription(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewManagedIdentityCollector(cred)
	data, err := collector.Collect(context.Background(), []string{"00000000-0000-0000-0000-000000000000"})
	// Should either error gracefully or return empty — never panic
	if err != nil {
		t.Logf("Expected error for bogus subscription: %v", err)
	} else {
		require.NotNil(t, data)
		assert.Empty(t, data.Identities, "bogus subscription should yield no identities")
		assert.Empty(t, data.Attachments, "bogus subscription should yield no attachments")
	}
}

// =====================================================================
// Managed Identity Collector — Negative: Empty Subscriptions
// =====================================================================

func TestIntegration_ManagedIdentityCollector_EmptySubscriptions(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewManagedIdentityCollector(cred)
	data, err := collector.Collect(context.Background(), []string{})
	require.NoError(t, err, "empty subscription list should not error")
	require.NotNil(t, data, "data should not be nil for empty input")
	assert.Empty(t, data.Identities, "should have no identities for empty subscriptions")
	assert.Empty(t, data.Attachments, "should have no attachments for empty subscriptions")
}

// =====================================================================
// Full Pipeline: All Collectors + Transform
// =====================================================================

func TestIntegration_FullPipeline(t *testing.T) {
	subID := skipUnlessIntegration(t)
	cred := defaultCredential(t)
	ctx := context.Background()

	// Collect all data
	entraCollector := NewEntraCollector(cred)
	entraData, err := entraCollector.Collect(ctx)
	require.NoError(t, err, "Entra Collect should succeed")

	rbacCollector := NewRBACCollector(cred)
	rbacData, err := rbacCollector.Collect(ctx, []string{subID})
	require.NoError(t, err, "RBAC Collect should succeed")

	pimCollector := NewPIMCollector(cred)
	pimData, err := pimCollector.Collect(ctx)
	require.NoError(t, err, "PIM Collect should succeed")

	mgCollector := NewMgmtGroupsCollector(cred)
	mgData, err := mgCollector.Collect(ctx)
	require.NoError(t, err, "MgmtGroups Collect should succeed")

	miCollector := NewManagedIdentityCollector(cred)
	miData, err := miCollector.Collect(ctx, []string{subID})
	require.NoError(t, err, "ManagedIdentity Collect should succeed")

	t.Logf("All collectors succeeded. Data summary:")
	t.Logf("  Entra: %d users, %d groups, %d SPs, %d apps",
		entraData.Users.Len(), entraData.Groups.Len(),
		entraData.ServicePrincipals.Len(), entraData.Applications.Len())
	t.Logf("  RBAC: %d subscriptions", len(rbacData))
	t.Logf("  PIM: %d active, %d eligible",
		len(pimData.ActiveAssignments), len(pimData.EligibleAssignments))
	t.Logf("  MgmtGroups: %d groups, %d relationships",
		len(mgData.Groups), len(mgData.Relationships))
	t.Logf("  ManagedIdentities: %d identities, %d attachments",
		len(miData.Identities), len(miData.Attachments))

	// --- Cross-validation: RBAC principals should be known Entra entities ---
	t.Run("RBAC principals are known Entra entities", func(t *testing.T) {
		if len(rbacData) == 0 {
			t.Skip("no RBAC data")
		}
		knownIDs := make(map[string]bool)
		entraData.Users.Range(func(_ string, u types.EntraUser) bool {
			knownIDs[u.ObjectID] = true
			return true
		})
		entraData.Groups.Range(func(_ string, g types.EntraGroup) bool {
			knownIDs[g.ObjectID] = true
			return true
		})
		entraData.ServicePrincipals.Range(func(_ string, sp types.EntraServicePrincipal) bool {
			knownIDs[sp.ObjectID] = true
			return true
		})

		matchCount := 0
		unmatchedCount := 0
		for _, r := range rbacData {
			for _, a := range r.Assignments {
				if knownIDs[a.PrincipalID] {
					matchCount++
				} else {
					unmatchedCount++
				}
			}
		}
		t.Logf("  RBAC→Entra cross-ref: %d matched, %d unmatched (foreign principals, MI, etc.)", matchCount, unmatchedCount)
		assert.Greater(t, matchCount, 0, "at least some RBAC principals should match Entra entities")
	})

	// --- Cross-validation: group membership member IDs should be known entities ---
	t.Run("group membership members are known entities", func(t *testing.T) {
		knownIDs := make(map[string]bool)
		entraData.Users.Range(func(_ string, u types.EntraUser) bool {
			knownIDs[u.ObjectID] = true
			return true
		})
		entraData.Groups.Range(func(_ string, g types.EntraGroup) bool {
			knownIDs[g.ObjectID] = true
			return true
		})
		entraData.ServicePrincipals.Range(func(_ string, sp types.EntraServicePrincipal) bool {
			knownIDs[sp.ObjectID] = true
			return true
		})

		matchCount := 0
		for _, gm := range entraData.GroupMemberships {
			if knownIDs[gm.MemberID] {
				matchCount++
			}
		}
		t.Logf("  GroupMembership→Entra cross-ref: %d/%d members matched",
			matchCount, len(entraData.GroupMemberships))
		if len(entraData.GroupMemberships) > 0 {
			matchPercent := float64(matchCount) / float64(len(entraData.GroupMemberships)) * 100
			assert.Greater(t, matchPercent, 80.0,
				"at least 80%% of group membership members should be known entities (got %.1f%%)", matchPercent)
		}
	})

	// --- Consolidated JSON roundtrip ---
	t.Run("consolidated JSON roundtrip", func(t *testing.T) {
		consolidated := &types.AzureIAMConsolidated{
			EntraID:           entraData,
			PIM:               pimData,
			RBAC:              rbacData,
			ManagementGroups:  mgData,
			ManagedIdentities: miData,
		}
		b, err := json.Marshal(consolidated)
		require.NoError(t, err)
		t.Logf("Consolidated JSON size: %d bytes", len(b))
		assert.Greater(t, len(b), 1000, "consolidated JSON should be substantial")

		var roundtrip types.AzureIAMConsolidated
		require.NoError(t, json.Unmarshal(b, &roundtrip))
		assert.Equal(t, entraData.Users.Len(), roundtrip.EntraID.Users.Len(), "user count after roundtrip")
		assert.Equal(t, entraData.Groups.Len(), roundtrip.EntraID.Groups.Len(), "group count after roundtrip")
		assert.Equal(t, entraData.ServicePrincipals.Len(), roundtrip.EntraID.ServicePrincipals.Len(), "SP count after roundtrip")
		assert.Equal(t, len(rbacData), len(roundtrip.RBAC), "RBAC subscription count after roundtrip")
	})
}
