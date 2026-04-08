package analyze

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

func TestCheckMFARequiredAdmins_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "Require MFA for admins",
				State:           "enabled",
				IncludeRoles:    []string{"All"},
				BuiltInControls: []string{"mfa"},
			},
		},
	}

	result, err := checkMFARequiredAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckMFARequiredAdmins_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
	}

	result, err := checkMFARequiredAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

func TestCheckMFARequiredAdmins_Fail_DisabledPolicy(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "MFA for admins (disabled)",
				State:           "disabled",
				IncludeRoles:    []string{"All"},
				BuiltInControls: []string{"mfa"},
			},
		},
	}

	result, err := checkMFARequiredAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail for disabled policy")
	}
}

func TestCheckMFARequiredAdmins_Pass_SpecificRoles(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:          "policy-1",
				DisplayName: "MFA for Global Admins",
				State:       "enabled",
				// Global Administrator role template ID
				IncludeRoles:    []string{"62e90394-69f5-4237-9190-012177145e10"},
				BuiltInControls: []string{"mfa"},
			},
		},
	}

	result, err := checkMFARequiredAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass for specific admin role, got: %s", result.Message)
	}
}

func TestCheckMFARequiredAllUsers_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "MFA for all users",
				State:               "enabled",
				IncludeUsers:        []string{"All"},
				IncludeApplications: []string{"All"},
				BuiltInControls:     []string{"mfa"},
			},
		},
	}

	result, err := checkMFARequiredAllUsers(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckMFARequiredAllUsers_Fail_NotAllApps(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "MFA for all users but specific app",
				State:               "enabled",
				IncludeUsers:        []string{"All"},
				IncludeApplications: []string{"some-app-id"},
				BuiltInControls:     []string{"mfa"},
			},
		},
	}

	result, err := checkMFARequiredAllUsers(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when not targeting all apps")
	}
}

func TestCheckBlockLegacyAuth_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "Block legacy auth",
				State:           "enabled",
				IncludeUsers:    []string{"All"},
				ClientAppTypes:  []string{"exchangeActiveSync", "other"},
				BuiltInControls: []string{"block"},
			},
		},
	}

	result, err := checkBlockLegacyAuth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckBlockLegacyAuth_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
	}

	result, err := checkBlockLegacyAuth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

func TestCheckGuestAccessRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			GuestUserRoleID: "2af84b1e-32c8-42b7-82bc-daa82404023b",
		},
	}

	result, err := checkGuestAccessRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckGuestAccessRestricted_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			GuestUserRoleID: "10dae51f-b6af-4016-8d66-8c2a99b929b3", // default
		},
	}

	result, err := checkGuestAccessRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail for non-restrictive guest role ID")
	}
}

func TestCheckUserConsentDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToCreateApps: false,
			},
		},
	}

	result, err := checkUserConsentDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckUserConsentDisabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToCreateApps: true,
			},
		},
	}

	result, err := checkUserConsentDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when user consent is allowed")
	}
}

// ---------------------------------------------------------------------------
// Negative / edge-case tests for checkMFARequiredAdmins
// ---------------------------------------------------------------------------

func TestCheckMFARequiredAdmins_EmptyPolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                  "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{},
	}

	result, err := checkMFARequiredAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty policies slice")
	}
}

func TestCheckMFARequiredAdmins_PolicyEnabledNoMFA(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "Admin policy without MFA",
				State:           "enabled",
				IncludeRoles:    []string{"All"},
				BuiltInControls: []string{"compliantDevice"},
			},
		},
	}

	result, err := checkMFARequiredAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when enabled policy targets admin roles but does not require MFA")
	}
}

func TestCheckMFARequiredAdmins_MultiplePoliciesOnlyOneMatches(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-disabled",
				DisplayName:     "Disabled MFA for admins",
				State:           "disabled",
				IncludeRoles:    []string{"All"},
				BuiltInControls: []string{"mfa"},
			},
			{
				ID:              "policy-enabled",
				DisplayName:     "Enabled MFA for admins",
				State:           "enabled",
				IncludeRoles:    []string{"All"},
				BuiltInControls: []string{"mfa"},
			},
		},
	}

	result, err := checkMFARequiredAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when at least one enabled policy matches, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// Negative / edge-case tests for checkMFARequiredAllUsers
// ---------------------------------------------------------------------------

func TestCheckMFARequiredAllUsers_EmptyPolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                  "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{},
	}

	result, err := checkMFARequiredAllUsers(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty policies slice")
	}
}

func TestCheckMFARequiredAllUsers_CaseSensitivity(t *testing.T) {
	// "all" lowercase instead of "All" - containsStr is case-sensitive
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "MFA for all users lowercase",
				State:               "enabled",
				IncludeUsers:        []string{"all"},
				IncludeApplications: []string{"All"},
				BuiltInControls:     []string{"mfa"},
			},
		},
	}

	result, err := checkMFARequiredAllUsers(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when IncludeUsers has 'all' (lowercase) instead of 'All'")
	}
}

func TestCheckMFARequiredAllUsers_UsersAllButAppsSpecific(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "MFA all users specific app",
				State:               "enabled",
				IncludeUsers:        []string{"All"},
				IncludeApplications: []string{"specific-app-id"},
				BuiltInControls:     []string{"mfa"},
			},
		},
	}

	result, err := checkMFARequiredAllUsers(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when users=All but apps is specific")
	}
}

// ---------------------------------------------------------------------------
// Negative / edge-case tests for checkBlockLegacyAuth
// ---------------------------------------------------------------------------

func TestCheckBlockLegacyAuth_EmptyPolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                  "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{},
	}

	result, err := checkBlockLegacyAuth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty policies slice")
	}
}

func TestCheckBlockLegacyAuth_ReportOnlyPolicy(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "Block legacy auth (report only)",
				State:           "enabledForReportingButNotEnforced",
				IncludeUsers:    []string{"All"},
				ClientAppTypes:  []string{"exchangeActiveSync", "other"},
				BuiltInControls: []string{"block"},
			},
		},
	}

	result, err := checkBlockLegacyAuth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail for report-only policy (state != enabled)")
	}
}

func TestCheckBlockLegacyAuth_NoBlockControl(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "Legacy auth MFA only",
				State:           "enabled",
				IncludeUsers:    []string{"All"},
				ClientAppTypes:  []string{"exchangeActiveSync", "other"},
				BuiltInControls: []string{"mfa"},
			},
		},
	}

	result, err := checkBlockLegacyAuth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when legacy clients targeted but no block control")
	}
}

// ---------------------------------------------------------------------------
// Negative / edge-case tests for checkGuestAccessRestricted
// ---------------------------------------------------------------------------

func TestCheckGuestAccessRestricted_EmptyRoleID(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			GuestUserRoleID: "",
		},
	}

	result, err := checkGuestAccessRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty GuestUserRoleID")
	}
}

func TestCheckGuestAccessRestricted_NilPolicy(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:            "test-tenant",
		AuthorizationPolicy: nil,
	}

	result, err := checkGuestAccessRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil AuthorizationPolicy")
	}
}

// ---------------------------------------------------------------------------
// Negative / edge-case tests for checkUserConsentDisabled
// ---------------------------------------------------------------------------

func TestCheckUserConsentDisabled_NilPermissions(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: nil,
		},
	}

	result, err := checkUserConsentDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with non-nil AuthorizationPolicy but nil DefaultUserRolePermissions")
	}
}
