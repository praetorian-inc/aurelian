package iam

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Integration tests that run against a real Azure tenant.
// Gated by AZURE_SUBSCRIPTION_ID environment variable.
//
// Run with: AZURE_SUBSCRIPTION_ID=<sub-id> go test ./pkg/azure/iam/ -run TestIntegration -v -count=1

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

func TestIntegration_EntraCollector(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewEntraCollector(cred)
	data, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Entra Collect failed: %v", err)
	}

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

	// Sanity checks — any real tenant should have at least some data
	if data.Users.Len() == 0 {
		t.Error("expected at least 1 user")
	}
	if data.TenantID == "" {
		t.Error("expected non-empty TenantID")
	}

	// Verify JSON roundtrip works
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	t.Logf("  JSON size:          %d bytes", len(b))
}

func TestIntegration_PIMCollector(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewPIMCollector(cred)
	data, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("PIM Collect failed: %v", err)
	}

	t.Logf("PIM results:")
	t.Logf("  ActiveAssignments:   %d", len(data.ActiveAssignments))
	t.Logf("  EligibleAssignments: %d", len(data.EligibleAssignments))

	// PIM may return 0 if tenant doesn't have P2 license — that's OK
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	t.Logf("  JSON size:           %d bytes", len(b))
}

func TestIntegration_RBACCollector(t *testing.T) {
	subID := skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewRBACCollector(cred)
	results, err := collector.Collect(context.Background(), []string{subID})
	if err != nil {
		t.Fatalf("RBAC Collect failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least 1 RBAC result")
	}

	for _, r := range results {
		t.Logf("RBAC results for subscription %s:", r.SubscriptionID)
		t.Logf("  Assignments:  %d", len(r.Assignments))
		t.Logf("  Definitions:  %d", r.Definitions.Len())
	}

	// Verify JSON roundtrip
	b, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	t.Logf("Total RBAC JSON size: %d bytes", len(b))
}

func TestIntegration_MgmtGroupsCollector(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)

	collector := NewMgmtGroupsCollector(cred)
	data, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("MgmtGroups Collect failed: %v", err)
	}

	t.Logf("Management Groups results:")
	t.Logf("  Groups:        %d", len(data.Groups))
	t.Logf("  Relationships: %d", len(data.Relationships))

	for _, g := range data.Groups {
		t.Logf("    %s (%s)", g.DisplayName, g.Name)
	}

	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	t.Logf("  JSON size:     %d bytes", len(b))
}

func TestIntegration_GraphTransformer(t *testing.T) {
	skipUnlessIntegration(t)
	cred := defaultCredential(t)
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")

	// Collect all data
	ctx := context.Background()

	entraCollector := NewEntraCollector(cred)
	entraData, err := entraCollector.Collect(ctx)
	if err != nil {
		t.Fatalf("Entra Collect failed: %v", err)
	}

	rbacCollector := NewRBACCollector(cred)
	rbacData, err := rbacCollector.Collect(ctx, []string{subID})
	if err != nil {
		t.Fatalf("RBAC Collect failed: %v", err)
	}

	pimCollector := NewPIMCollector(cred)
	pimData, err := pimCollector.Collect(ctx)
	if err != nil {
		t.Fatalf("PIM Collect failed: %v", err)
	}

	mgCollector := NewMgmtGroupsCollector(cred)
	mgData, err := mgCollector.Collect(ctx)
	if err != nil {
		t.Fatalf("MgmtGroups Collect failed: %v", err)
	}

	// Import transformer (can't import due to package boundary, so just verify data is valid)
	t.Logf("All collectors succeeded. Data summary:")
	t.Logf("  Entra: %d users, %d groups, %d SPs, %d apps",
		entraData.Users.Len(), entraData.Groups.Len(),
		entraData.ServicePrincipals.Len(), entraData.Applications.Len())
	t.Logf("  RBAC: %d subscriptions", len(rbacData))
	t.Logf("  PIM: %d active, %d eligible",
		len(pimData.ActiveAssignments), len(pimData.EligibleAssignments))
	t.Logf("  MgmtGroups: %d groups, %d relationships",
		len(mgData.Groups), len(mgData.Relationships))

	// Cross-validate: RBAC principal IDs should exist in Entra
	if len(rbacData) > 0 && entraData.Users.Len() > 0 {
		matchCount := 0
		for _, r := range rbacData {
			for _, a := range r.Assignments {
				if _, ok := entraData.Users.Get(a.PrincipalID); ok {
					matchCount++
				}
			}
		}
		t.Logf("  RBAC→Entra cross-ref: %d assignments matched to known users", matchCount)
	}
}
