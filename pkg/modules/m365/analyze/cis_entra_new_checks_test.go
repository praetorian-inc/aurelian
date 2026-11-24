package analyze

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

func boolPtr(b bool) *bool     { return &b }
func int32Ptr(i int32) *int32  { return &i }

// ---------------------------------------------------------------------------
// 5.2.2.5 - checkPhishingResistantMFAAdmins
// ---------------------------------------------------------------------------

func TestCheckPhishingResistantMFAAdmins_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:          "policy-1",
				DisplayName: "Phishing-resistant MFA for admins",
				State:       "enabled",
				IncludeRoles: []string{"All"},
				AuthenticationStrength: &databag.AuthenticationStrengthPolicy{
					DisplayName:         "Phishing-resistant MFA",
					AllowedCombinations: []string{"fido2", "windowsHelloForBusiness"},
				},
			},
		},
	}

	result, err := checkPhishingResistantMFAAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckPhishingResistantMFAAdmins_Pass_ByName(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:           "policy-1",
				DisplayName:  "Require phishing-resistant MFA for admins",
				State:        "enabled",
				IncludeRoles: []string{"62e90394-69f5-4237-9190-012177145e10"},
				AuthenticationStrength: &databag.AuthenticationStrengthPolicy{
					DisplayName: "Phishing-Resistant MFA",
				},
			},
		},
	}

	result, err := checkPhishingResistantMFAAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckPhishingResistantMFAAdmins_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkPhishingResistantMFAAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

func TestCheckPhishingResistantMFAAdmins_Fail_NoAuthStrength(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "MFA for admins",
				State:           "enabled",
				IncludeRoles:    []string{"All"},
				BuiltInControls: []string{"mfa"},
			},
		},
	}

	result, err := checkPhishingResistantMFAAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail without phishing-resistant auth strength")
	}
}

// ---------------------------------------------------------------------------
// 5.2.2.6 - checkUserRiskBasedCA
// ---------------------------------------------------------------------------

func TestCheckUserRiskBasedCA_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:             "policy-1",
				DisplayName:    "User risk CA policy",
				State:          "enabled",
				IncludeUsers:   []string{"All"},
				UserRiskLevels: []string{"high", "medium"},
			},
		},
	}

	result, err := checkUserRiskBasedCA(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckUserRiskBasedCA_Fail_NoRiskLevels(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:           "policy-1",
				DisplayName:  "Generic CA policy",
				State:        "enabled",
				IncludeUsers: []string{"All"},
			},
		},
	}

	result, err := checkUserRiskBasedCA(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no user risk levels")
	}
}

func TestCheckUserRiskBasedCA_Fail_Disabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:             "policy-1",
				DisplayName:    "User risk CA (disabled)",
				State:          "disabled",
				IncludeUsers:   []string{"All"},
				UserRiskLevels: []string{"high"},
			},
		},
	}

	result, err := checkUserRiskBasedCA(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail for disabled policy")
	}
}

// ---------------------------------------------------------------------------
// 5.2.2.7 - checkSignInRiskBasedCA
// ---------------------------------------------------------------------------

func TestCheckSignInRiskBasedCA_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:               "policy-1",
				DisplayName:      "Sign-in risk CA policy",
				State:            "enabled",
				IncludeUsers:     []string{"All"},
				SignInRiskLevels: []string{"high", "medium"},
			},
		},
	}

	result, err := checkSignInRiskBasedCA(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSignInRiskBasedCA_Fail(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkSignInRiskBasedCA(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ---------------------------------------------------------------------------
// 5.2.2.9 - checkManagedDeviceRequired
// ---------------------------------------------------------------------------

func TestCheckManagedDeviceRequired_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "Require compliant device",
				State:               "enabled",
				IncludeUsers:        []string{"All"},
				IncludeApplications: []string{"All"},
				BuiltInControls:     []string{"compliantDevice"},
			},
		},
	}

	result, err := checkManagedDeviceRequired(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckManagedDeviceRequired_Pass_DomainJoined(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "Require domain joined device",
				State:               "enabled",
				IncludeUsers:        []string{"All"},
				IncludeApplications: []string{"All"},
				BuiltInControls:     []string{"domainJoinedDevice"},
			},
		},
	}

	result, err := checkManagedDeviceRequired(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckManagedDeviceRequired_Fail_NotAllApps(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "Require device for some apps",
				State:               "enabled",
				IncludeUsers:        []string{"All"},
				IncludeApplications: []string{"some-app-id"},
				BuiltInControls:     []string{"compliantDevice"},
			},
		},
	}

	result, err := checkManagedDeviceRequired(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when not targeting all apps")
	}
}

// ---------------------------------------------------------------------------
// 5.2.2.10 - checkManagedDeviceForMFARegistration
// ---------------------------------------------------------------------------

func TestCheckManagedDeviceForMFARegistration_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                 "policy-1",
				DisplayName:        "Require device for MFA registration",
				State:              "enabled",
				IncludeUserActions: []string{"urn:user:registersecurityinfo"},
				BuiltInControls:    []string{"compliantDevice"},
			},
		},
	}

	result, err := checkManagedDeviceForMFARegistration(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckManagedDeviceForMFARegistration_Fail(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkManagedDeviceForMFARegistration(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

func TestCheckManagedDeviceForMFARegistration_Fail_WrongAction(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                 "policy-1",
				DisplayName:        "Require device for some action",
				State:              "enabled",
				IncludeUserActions: []string{"urn:user:someotheraction"},
				BuiltInControls:    []string{"compliantDevice"},
			},
		},
	}

	result, err := checkManagedDeviceForMFARegistration(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with wrong user action")
	}
}

// ---------------------------------------------------------------------------
// 5.2.2.11 - checkAdminSignInFrequency
// ---------------------------------------------------------------------------

func TestCheckAdminSignInFrequency_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                     "policy-1",
				DisplayName:            "Admin sign-in frequency",
				State:                  "enabled",
				IncludeRoles:           []string{"All"},
				SignInFrequencyEnabled: true,
				SignInFrequencyValue:   int32Ptr(4),
				SignInFrequencyUnit:    "hours",
			},
		},
	}

	result, err := checkAdminSignInFrequency(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckAdminSignInFrequency_Fail_NotEnabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                     "policy-1",
				DisplayName:            "Admin policy without frequency",
				State:                  "enabled",
				IncludeRoles:           []string{"All"},
				SignInFrequencyEnabled: false,
			},
		},
	}

	result, err := checkAdminSignInFrequency(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail without sign-in frequency enabled")
	}
}

func TestCheckAdminSignInFrequency_Fail_NilValue(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                     "policy-1",
				DisplayName:            "Admin policy nil frequency value",
				State:                  "enabled",
				IncludeRoles:           []string{"All"},
				SignInFrequencyEnabled: true,
				SignInFrequencyValue:   nil,
			},
		},
	}

	result, err := checkAdminSignInFrequency(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when sign-in frequency value is nil")
	}
}

// ---------------------------------------------------------------------------
// 5.2.2.12 - checkDeviceCodeFlowBlocked
// ---------------------------------------------------------------------------

func TestCheckDeviceCodeFlowBlocked_Pass_TransferMethods(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "Block device code flow",
				State:           "enabled",
				IncludeUsers:    []string{"All"},
				TransferMethods: []string{"deviceCodeFlow"},
				BuiltInControls: []string{"block"},
			},
		},
	}

	result, err := checkDeviceCodeFlowBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckDeviceCodeFlowBlocked_Pass_ClientAppTypes(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "Block device code via clientAppTypes",
				State:           "enabled",
				IncludeUsers:    []string{"All"},
				ClientAppTypes:  []string{"deviceCode"},
				BuiltInControls: []string{"block"},
			},
		},
	}

	result, err := checkDeviceCodeFlowBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckDeviceCodeFlowBlocked_Fail(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkDeviceCodeFlowBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

func TestCheckDeviceCodeFlowBlocked_Fail_NotBlocking(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "Device code flow with MFA only",
				State:           "enabled",
				IncludeUsers:    []string{"All"},
				TransferMethods: []string{"deviceCodeFlow"},
				BuiltInControls: []string{"mfa"},
			},
		},
	}

	result, err := checkDeviceCodeFlowBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when policy requires MFA but does not block")
	}
}

// ---------------------------------------------------------------------------
// 5.1.2.3 - checkDefaultUsersCannotCreateTenants
// ---------------------------------------------------------------------------

func TestCheckDefaultUsersCannotCreateTenants_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToCreateTenants: false,
			},
		},
	}

	result, err := checkDefaultUsersCannotCreateTenants(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckDefaultUsersCannotCreateTenants_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToCreateTenants: true,
			},
		},
	}

	result, err := checkDefaultUsersCannotCreateTenants(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when users can create tenants")
	}
}

func TestCheckDefaultUsersCannotCreateTenants_Fail_NilPolicy(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkDefaultUsersCannotCreateTenants(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil authorization policy")
	}
}

// ---------------------------------------------------------------------------
// 5.1.2.4 - checkAdminPortalsRestricted
// ---------------------------------------------------------------------------

func TestCheckAdminPortalsRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AdminPortalSettings: &databag.AdminPortalSettings{
			RestrictNonAdminUsers: true,
		},
	}

	result, err := checkAdminPortalsRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckAdminPortalsRestricted_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AdminPortalSettings: &databag.AdminPortalSettings{
			RestrictNonAdminUsers: false,
		},
	}

	result, err := checkAdminPortalsRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when admin portals are not restricted")
	}
}

func TestCheckAdminPortalsRestricted_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkAdminPortalsRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil admin portal settings")
	}
}

// ---------------------------------------------------------------------------
// 5.1.3.1 - checkDynamicGroupForGuests
// ---------------------------------------------------------------------------

func TestCheckDynamicGroupForGuests_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Groups: []databag.Group{
			{
				ID:             "group-1",
				DisplayName:    "Guest Users Dynamic Group",
				GroupTypes:     []string{"DynamicMembership"},
				MembershipRule: "(user.userType -eq \"Guest\")",
			},
		},
	}

	result, err := checkDynamicGroupForGuests(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckDynamicGroupForGuests_Fail_NoGroups(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkDynamicGroupForGuests(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no groups")
	}
}

func TestCheckDynamicGroupForGuests_Fail_NotDynamic(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Groups: []databag.Group{
			{
				ID:             "group-1",
				DisplayName:    "Static Guest Group",
				GroupTypes:     []string{"Unified"},
				MembershipRule: "(user.userType -eq \"Guest\")",
			},
		},
	}

	result, err := checkDynamicGroupForGuests(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with non-dynamic group")
	}
}

// ---------------------------------------------------------------------------
// 5.1.5.2 - checkAdminConsentWorkflowEnabled
// ---------------------------------------------------------------------------

func TestCheckAdminConsentWorkflowEnabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AdminConsentPolicy: &databag.AdminConsentPolicy{
			IsEnabled:        true,
			NotifyReviewers:  true,
			RemindersEnabled: true,
		},
	}

	result, err := checkAdminConsentWorkflowEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckAdminConsentWorkflowEnabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AdminConsentPolicy: &databag.AdminConsentPolicy{
			IsEnabled: false,
		},
	}

	result, err := checkAdminConsentWorkflowEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when admin consent workflow is disabled")
	}
}

func TestCheckAdminConsentWorkflowEnabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkAdminConsentWorkflowEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil admin consent policy")
	}
}

// ---------------------------------------------------------------------------
// 5.1.6.1 - checkThirdPartyAppsNotAllowed
// ---------------------------------------------------------------------------

func TestCheckThirdPartyAppsNotAllowed_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToCreateApps: false,
			},
		},
	}

	result, err := checkThirdPartyAppsNotAllowed(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckThirdPartyAppsNotAllowed_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToCreateApps: true,
			},
		},
	}

	result, err := checkThirdPartyAppsNotAllowed(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when users can create apps")
	}
}

func TestCheckThirdPartyAppsNotAllowed_Fail_NilPermissions(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: nil,
		},
	}

	result, err := checkThirdPartyAppsNotAllowed(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil permissions")
	}
}

// ---------------------------------------------------------------------------
// 5.1.6.2 - checkGuestUserAccessRestrictions
// ---------------------------------------------------------------------------

func TestCheckGuestUserAccessRestrictions_Pass_MostRestrictive(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			GuestUserRoleID: "2af84b1e-32c8-42b7-82bc-daa82404023b",
		},
	}

	result, err := checkGuestUserAccessRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckGuestUserAccessRestrictions_Pass_LimitedAccess(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			GuestUserRoleID: "10dae51f-b6af-4016-8d66-8c2a99b929b3",
		},
	}

	result, err := checkGuestUserAccessRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass for limited access, got: %s", result.Message)
	}
}

func TestCheckGuestUserAccessRestrictions_Fail_SameAsMember(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			GuestUserRoleID: "a0b1b346-4d3e-4e8b-98f8-753987be4970",
		},
	}

	result, err := checkGuestUserAccessRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail for same-as-member guest role")
	}
}

func TestCheckGuestUserAccessRestrictions_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkGuestUserAccessRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil authorization policy")
	}
}

// ---------------------------------------------------------------------------
// 5.1.6.3 - checkGuestInvitesRestricted
// ---------------------------------------------------------------------------

func TestCheckGuestInvitesRestricted_Pass_AdminsAndGuestInviters(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			AllowInvitesFrom: "adminsAndGuestInviters",
		},
	}

	result, err := checkGuestInvitesRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckGuestInvitesRestricted_Pass_None(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			AllowInvitesFrom: "none",
		},
	}

	result, err := checkGuestInvitesRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckGuestInvitesRestricted_Fail_Everyone(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			AllowInvitesFrom: "everyone",
		},
	}

	result, err := checkGuestInvitesRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when everyone can invite guests")
	}
}

func TestCheckGuestInvitesRestricted_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkGuestInvitesRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil authorization policy")
	}
}

// ---------------------------------------------------------------------------
// 5.1.8.1 - checkPasswordHashSyncEnabled
// ---------------------------------------------------------------------------

func TestCheckPasswordHashSyncEnabled_Pass_Hybrid(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OnPremSyncSettings: &databag.OnPremSyncSettings{
			OnPremisesSyncEnabled:   true,
			PasswordHashSyncEnabled: true,
		},
	}

	result, err := checkPasswordHashSyncEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckPasswordHashSyncEnabled_Pass_CloudOnly(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OnPremSyncSettings: &databag.OnPremSyncSettings{
			OnPremisesSyncEnabled:   false,
			PasswordHashSyncEnabled: false,
		},
	}

	result, err := checkPasswordHashSyncEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass for cloud-only tenant, got: %s", result.Message)
	}
}

func TestCheckPasswordHashSyncEnabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OnPremSyncSettings: &databag.OnPremSyncSettings{
			OnPremisesSyncEnabled:   true,
			PasswordHashSyncEnabled: false,
		},
	}

	result, err := checkPasswordHashSyncEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when PHS is disabled for hybrid")
	}
}

func TestCheckPasswordHashSyncEnabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkPasswordHashSyncEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil on-prem sync settings")
	}
}

// ---------------------------------------------------------------------------
// 5.2.3.4 - checkUsersAreMFACapable
// ---------------------------------------------------------------------------

func TestCheckUsersAreMFACapable_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		CredentialUserRegistrationDetails: []databag.CredentialUserRegistrationDetail{
			{UserPrincipalName: "user1@test.com", IsMfaCapable: true},
			{UserPrincipalName: "user2@test.com", IsMfaCapable: true},
		},
	}

	result, err := checkUsersAreMFACapable(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckUsersAreMFACapable_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		CredentialUserRegistrationDetails: []databag.CredentialUserRegistrationDetail{
			{UserPrincipalName: "user1@test.com", IsMfaCapable: true},
			{UserPrincipalName: "user2@test.com", IsMfaCapable: false},
		},
	}

	result, err := checkUsersAreMFACapable(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when some users are not MFA capable")
	}
}

func TestCheckUsersAreMFACapable_Fail_Empty(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkUsersAreMFACapable(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no credential details")
	}
}

// ---------------------------------------------------------------------------
// 1.1.1 - checkAdminUsersCloudOnly
// ---------------------------------------------------------------------------

func TestCheckAdminUsersCloudOnly_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"user-1"},
			},
		},
		Users: []databag.User{
			{
				ID:                    "user-1",
				UserPrincipalName:     "admin@test.com",
				OnPremisesSyncEnabled: boolPtr(false),
			},
		},
	}

	result, err := checkAdminUsersCloudOnly(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckAdminUsersCloudOnly_Pass_NilSync(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"user-1"},
			},
		},
		Users: []databag.User{
			{
				ID:                    "user-1",
				UserPrincipalName:     "admin@test.com",
				OnPremisesSyncEnabled: nil,
			},
		},
	}

	result, err := checkAdminUsersCloudOnly(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when OnPremisesSyncEnabled is nil, got: %s", result.Message)
	}
}

func TestCheckAdminUsersCloudOnly_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"user-1"},
			},
		},
		Users: []databag.User{
			{
				ID:                    "user-1",
				UserPrincipalName:     "admin@test.com",
				OnPremisesSyncEnabled: boolPtr(true),
			},
		},
	}

	result, err := checkAdminUsersCloudOnly(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when admin user is synced from on-premises")
	}
}

func TestCheckAdminUsersCloudOnly_Fail_NoAdminRoles(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkAdminUsersCloudOnly(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no admin role members")
	}
}

// ---------------------------------------------------------------------------
// 1.1.2 - checkBreakGlassHasFIDO2
// ---------------------------------------------------------------------------

func TestCheckBreakGlassHasFIDO2_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Users: []databag.User{
			{
				ID:                "user-1",
				DisplayName:       "Break Glass Account 1",
				UserPrincipalName: "breakglass1@test.com",
				AuthMethods:       []string{"fido2"},
			},
			{
				ID:                "user-2",
				DisplayName:       "Emergency Access Account",
				UserPrincipalName: "emergency@test.com",
				AuthMethods:       []string{"fido2", "microsoftAuthenticator"},
			},
		},
	}

	result, err := checkBreakGlassHasFIDO2(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckBreakGlassHasFIDO2_Fail_NoFIDO2(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Users: []databag.User{
			{
				ID:                "user-1",
				DisplayName:       "Break Glass Account",
				UserPrincipalName: "breakglass@test.com",
				AuthMethods:       []string{"microsoftAuthenticator"},
			},
		},
	}

	result, err := checkBreakGlassHasFIDO2(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when break glass account lacks FIDO2")
	}
}

func TestCheckBreakGlassHasFIDO2_Fail_NoBreakGlassAccounts(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Users: []databag.User{
			{
				ID:                "user-1",
				DisplayName:       "Regular User",
				UserPrincipalName: "user@test.com",
			},
		},
	}

	result, err := checkBreakGlassHasFIDO2(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when no break-glass accounts exist")
	}
}

// ---------------------------------------------------------------------------
// 1.1.3 - checkGlobalAdminCount
// ---------------------------------------------------------------------------

func TestCheckGlobalAdminCount_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"user-1", "user-2", "user-3"},
			},
		},
	}

	result, err := checkGlobalAdminCount(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with 3 admins, got: %s", result.Message)
	}
}

func TestCheckGlobalAdminCount_Fail_TooFew(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"user-1"},
			},
		},
	}

	result, err := checkGlobalAdminCount(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with only 1 global admin")
	}
}

func TestCheckGlobalAdminCount_Fail_TooMany(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"u1", "u2", "u3", "u4", "u5"},
			},
		},
	}

	result, err := checkGlobalAdminCount(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with 5 global admins")
	}
}

func TestCheckGlobalAdminCount_Fail_Zero(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{},
			},
		},
	}

	result, err := checkGlobalAdminCount(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with 0 global admins")
	}
}

// ---------------------------------------------------------------------------
// EXTRA.1 - checkSMSVoiceAuthDisabled
// ---------------------------------------------------------------------------

func TestCheckSMSVoiceAuthDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthMethodsPolicy: &databag.AuthMethodsPolicy{
			AuthMethodConfigs: []databag.AuthMethodConfiguration{
				{MethodType: "sms", State: "disabled"},
				{MethodType: "voice", State: "disabled"},
				{MethodType: "fido2", State: "enabled"},
			},
		},
	}

	result, err := checkSMSVoiceAuthDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSMSVoiceAuthDisabled_Pass_NoWeakMethods(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthMethodsPolicy: &databag.AuthMethodsPolicy{
			AuthMethodConfigs: []databag.AuthMethodConfiguration{
				{MethodType: "fido2", State: "enabled"},
			},
		},
	}

	result, err := checkSMSVoiceAuthDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSMSVoiceAuthDisabled_Fail_SMSEnabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthMethodsPolicy: &databag.AuthMethodsPolicy{
			AuthMethodConfigs: []databag.AuthMethodConfiguration{
				{MethodType: "sms", State: "enabled"},
				{MethodType: "voice", State: "disabled"},
			},
		},
	}

	result, err := checkSMSVoiceAuthDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when SMS is enabled")
	}
}

func TestCheckSMSVoiceAuthDisabled_Fail_VoiceEnabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthMethodsPolicy: &databag.AuthMethodsPolicy{
			AuthMethodConfigs: []databag.AuthMethodConfiguration{
				{MethodType: "sms", State: "disabled"},
				{MethodType: "voice", State: "enabled"},
			},
		},
	}

	result, err := checkSMSVoiceAuthDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when Voice is enabled")
	}
}

func TestCheckSMSVoiceAuthDisabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkSMSVoiceAuthDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil auth methods policy")
	}
}

// ---------------------------------------------------------------------------
// EXTRA.2 - checkCACoversAllCloudApps
// ---------------------------------------------------------------------------

func TestCheckCACoversAllCloudApps_Pass_MFA(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "MFA for all apps",
				State:               "enabled",
				IncludeApplications: []string{"All"},
				BuiltInControls:     []string{"mfa"},
			},
		},
	}

	result, err := checkCACoversAllCloudApps(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckCACoversAllCloudApps_Pass_CompliantDevice(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "Compliant device for all apps",
				State:               "enabled",
				IncludeApplications: []string{"All"},
				BuiltInControls:     []string{"compliantDevice"},
			},
		},
	}

	result, err := checkCACoversAllCloudApps(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckCACoversAllCloudApps_Fail_NotAllApps(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "MFA for specific app",
				State:               "enabled",
				IncludeApplications: []string{"some-app"},
				BuiltInControls:     []string{"mfa"},
			},
		},
	}

	result, err := checkCACoversAllCloudApps(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when not covering all apps")
	}
}

func TestCheckCACoversAllCloudApps_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkCACoversAllCloudApps(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ===========================================================================
// Additional negative / edge-case tests
// ===========================================================================

// ---------------------------------------------------------------------------
// checkPhishingResistantMFAAdmins edge cases
// ---------------------------------------------------------------------------

func TestCheckPhishingResistantMFA_EmptyAllowedCombinations(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:           "policy-1",
				DisplayName:  "Phishing MFA empty combos",
				State:        "enabled",
				IncludeRoles: []string{"All"},
				AuthenticationStrength: &databag.AuthenticationStrengthPolicy{
					DisplayName:         "Custom strength",
					AllowedCombinations: []string{},
				},
			},
		},
	}

	result, err := checkPhishingResistantMFAAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when AuthenticationStrength has empty AllowedCombinations and non-phishing-resistant name")
	}
}

func TestCheckPhishingResistantMFA_NilAuthStrength(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                     "policy-1",
				DisplayName:            "Admin MFA no auth strength",
				State:                  "enabled",
				IncludeRoles:           []string{"All"},
				BuiltInControls:        []string{"mfa"},
				AuthenticationStrength: nil,
			},
		},
	}

	result, err := checkPhishingResistantMFAAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when AuthenticationStrength is nil on otherwise matching policy")
	}
}

func TestCheckPhishingResistantMFA_MixedPhishingMethods(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:           "policy-1",
				DisplayName:  "Mixed methods",
				State:        "enabled",
				IncludeRoles: []string{"All"},
				AuthenticationStrength: &databag.AuthenticationStrengthPolicy{
					DisplayName:         "Custom MFA",
					AllowedCombinations: []string{"fido2", "microsoftAuthenticatorPush"},
				},
			},
		},
	}

	result, err := checkPhishingResistantMFAAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when AllowedCombinations has a mix of FIDO2 and non-phishing-resistant methods")
	}
}

// ---------------------------------------------------------------------------
// checkUserRiskBasedCA edge cases
// ---------------------------------------------------------------------------

func TestCheckUserRiskBasedCA_EmptyRiskLevels(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:             "policy-1",
				DisplayName:    "User risk empty levels",
				State:          "enabled",
				IncludeUsers:   []string{"All"},
				UserRiskLevels: []string{},
			},
		},
	}

	result, err := checkUserRiskBasedCA(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when UserRiskLevels is empty slice (not nil)")
	}
}

// ---------------------------------------------------------------------------
// checkSignInRiskBasedCA edge cases
// ---------------------------------------------------------------------------

func TestCheckSignInRiskBasedCA_EmptyRiskLevels(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:               "policy-1",
				DisplayName:      "SignIn risk empty levels",
				State:            "enabled",
				IncludeUsers:     []string{"All"},
				SignInRiskLevels: []string{},
			},
		},
	}

	result, err := checkSignInRiskBasedCA(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when SignInRiskLevels is empty slice (not nil)")
	}
}

// ---------------------------------------------------------------------------
// checkManagedDeviceRequired edge cases
// ---------------------------------------------------------------------------

func TestCheckManagedDeviceRequired_NeitherControl(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "All users all apps but no device control",
				State:               "enabled",
				IncludeUsers:        []string{"All"},
				IncludeApplications: []string{"All"},
				BuiltInControls:     []string{"mfa"},
			},
		},
	}

	result, err := checkManagedDeviceRequired(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when neither compliantDevice nor domainJoinedDevice is required")
	}
}

// ---------------------------------------------------------------------------
// checkManagedDeviceForMFARegistration edge cases
// ---------------------------------------------------------------------------

func TestCheckManagedDeviceForMFA_EmptyUserActions(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                 "policy-1",
				DisplayName:        "Device required, empty user actions",
				State:              "enabled",
				IncludeUserActions: []string{},
				BuiltInControls:    []string{"compliantDevice"},
			},
		},
	}

	result, err := checkManagedDeviceForMFARegistration(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when IncludeUserActions is empty")
	}
}

// ---------------------------------------------------------------------------
// checkAdminSignInFrequency edge cases
// ---------------------------------------------------------------------------

func TestCheckAdminSignInFrequency_ZeroValue(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                     "policy-1",
				DisplayName:            "Admin sign-in frequency zero",
				State:                  "enabled",
				IncludeRoles:           []string{"All"},
				SignInFrequencyEnabled: true,
				SignInFrequencyValue:   int32Ptr(0),
				SignInFrequencyUnit:    "hours",
			},
		},
	}

	result, err := checkAdminSignInFrequency(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The check only verifies SignInFrequencyEnabled && Value != nil, so value=0 still passes
	if !result.Passed {
		t.Fatalf("expected check to pass even with zero frequency value (check only requires enabled + non-nil), got: %s", result.Message)
	}
}

func TestCheckAdminSignInFrequency_EnabledButNilValue(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                     "policy-1",
				DisplayName:            "Admin freq enabled nil value",
				State:                  "enabled",
				IncludeRoles:           []string{"All"},
				SignInFrequencyEnabled: true,
				SignInFrequencyValue:   nil,
			},
		},
	}

	result, err := checkAdminSignInFrequency(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when SignInFrequencyEnabled=true but Value is nil")
	}
}

// ---------------------------------------------------------------------------
// checkDeviceCodeFlowBlocked edge cases
// ---------------------------------------------------------------------------

func TestCheckDeviceCodeFlowBlocked_EmptyTransferMethods(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:              "policy-1",
				DisplayName:     "Block policy empty transfer methods",
				State:           "enabled",
				IncludeUsers:    []string{"All"},
				TransferMethods: []string{},
				ClientAppTypes:  []string{"browser", "mobileAppsAndDesktopClients"},
				BuiltInControls: []string{"block"},
			},
		},
	}

	result, err := checkDeviceCodeFlowBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when TransferMethods is empty and no deviceCode in ClientAppTypes")
	}
}

// ---------------------------------------------------------------------------
// checkGlobalAdminCount boundary tests
// ---------------------------------------------------------------------------

func TestCheckGlobalAdminCount_Boundary1(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"user-1"},
			},
		},
	}

	result, err := checkGlobalAdminCount(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with count=1 (too few, minimum is 2)")
	}
}

func TestCheckGlobalAdminCount_Boundary2(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"user-1", "user-2"},
			},
		},
	}

	result, err := checkGlobalAdminCount(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with count=2 (minimum valid), got: %s", result.Message)
	}
}

func TestCheckGlobalAdminCount_Boundary4(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"u1", "u2", "u3", "u4"},
			},
		},
	}

	result, err := checkGlobalAdminCount(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with count=4 (maximum valid), got: %s", result.Message)
	}
}

func TestCheckGlobalAdminCount_Boundary5(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"u1", "u2", "u3", "u4", "u5"},
			},
		},
	}

	result, err := checkGlobalAdminCount(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with count=5 (too many, maximum is 4)")
	}
}

func TestCheckGlobalAdminCount_NoGlobalAdminRole(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator, not Global Admin
				Members:        []string{"user-1", "user-2", "user-3"},
			},
		},
	}

	result, err := checkGlobalAdminCount(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when no role has globalAdminRoleTemplateID")
	}
}

// ---------------------------------------------------------------------------
// checkAdminUsersCloudOnly edge cases
// ---------------------------------------------------------------------------

func TestCheckAdminUsersCloudOnly_NilOnPremSync(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"user-1"},
			},
		},
		Users: []databag.User{
			{
				ID:                    "user-1",
				UserPrincipalName:     "admin@test.com",
				OnPremisesSyncEnabled: nil,
			},
		},
	}

	result, err := checkAdminUsersCloudOnly(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when OnPremisesSyncEnabled is nil (cloud-only), got: %s", result.Message)
	}
}

func TestCheckAdminUsersCloudOnly_NoUsersFound(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"user-1", "user-2"},
			},
		},
		Users: []databag.User{
			// No users match the admin IDs
			{
				ID:                    "user-99",
				UserPrincipalName:     "unrelated@test.com",
				OnPremisesSyncEnabled: boolPtr(true),
			},
		},
	}

	result, err := checkAdminUsersCloudOnly(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Admin IDs exist but no matching user objects found; synced count = 0, so passes
	if !result.Passed {
		t.Fatalf("expected check to pass when admin IDs exist but no matching users found, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// checkBreakGlassHasFIDO2 edge cases
// ---------------------------------------------------------------------------

func TestCheckBreakGlassHasFIDO2_EmptyAuthMethods(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Users: []databag.User{
			{
				ID:                "user-1",
				DisplayName:       "Break Glass Account",
				UserPrincipalName: "breakglass@test.com",
				AuthMethods:       []string{},
			},
		},
	}

	result, err := checkBreakGlassHasFIDO2(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when break glass user has empty AuthMethods")
	}
}

func TestCheckBreakGlassHasFIDO2_MultipleMixed(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Users: []databag.User{
			{
				ID:                "user-1",
				DisplayName:       "Break Glass Account 1",
				UserPrincipalName: "breakglass1@test.com",
				AuthMethods:       []string{"fido2"},
			},
			{
				ID:                "user-2",
				DisplayName:       "Emergency Access Account 2",
				UserPrincipalName: "emergency2@test.com",
				AuthMethods:       []string{"microsoftAuthenticator"},
			},
		},
	}

	result, err := checkBreakGlassHasFIDO2(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when one break-glass has FIDO2 but the other does not")
	}
}

// ---------------------------------------------------------------------------
// checkDynamicGroupForGuests edge cases
// ---------------------------------------------------------------------------

func TestCheckDynamicGroupForGuests_EmptyMembershipRule(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Groups: []databag.Group{
			{
				ID:             "group-1",
				DisplayName:    "Dynamic Group Empty Rule",
				GroupTypes:     []string{"DynamicMembership"},
				MembershipRule: "",
			},
		},
	}

	result, err := checkDynamicGroupForGuests(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when dynamic group has empty MembershipRule")
	}
}

func TestCheckDynamicGroupForGuests_NoDynamicGroups(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Groups: []databag.Group{
			{
				ID:             "group-1",
				DisplayName:    "Static Group for Guests",
				GroupTypes:     []string{"Unified"},
				MembershipRule: "(user.userType -eq \"Guest\")",
			},
			{
				ID:          "group-2",
				DisplayName: "Another Static Group",
				GroupTypes:  []string{},
			},
		},
	}

	result, err := checkDynamicGroupForGuests(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when groups exist but none are dynamic")
	}
}

// ---------------------------------------------------------------------------
// checkPasswordHashSyncEnabled edge cases
// ---------------------------------------------------------------------------

func TestCheckPasswordHashSync_NilSettings(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:           "test-tenant",
		OnPremSyncSettings: nil,
	}

	result, err := checkPasswordHashSyncEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil OnPremSyncSettings")
	}
}

func TestCheckPasswordHashSync_CloudOnlyTenant(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OnPremSyncSettings: &databag.OnPremSyncSettings{
			OnPremisesSyncEnabled:   false,
			PasswordHashSyncEnabled: false,
		},
	}

	result, err := checkPasswordHashSyncEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass for cloud-only tenant (N/A), got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// checkUsersAreMFACapable edge cases
// ---------------------------------------------------------------------------

func TestCheckUsersAreMFACapable_AllCapable(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		CredentialUserRegistrationDetails: []databag.CredentialUserRegistrationDetail{
			{UserPrincipalName: "user1@test.com", IsMfaCapable: true},
			{UserPrincipalName: "user2@test.com", IsMfaCapable: true},
			{UserPrincipalName: "user3@test.com", IsMfaCapable: true},
		},
	}

	result, err := checkUsersAreMFACapable(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when all users are MFA capable, got: %s", result.Message)
	}
}

func TestCheckUsersAreMFACapable_SomeMixed(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		CredentialUserRegistrationDetails: []databag.CredentialUserRegistrationDetail{
			{UserPrincipalName: "user1@test.com", IsMfaCapable: true},
			{UserPrincipalName: "user2@test.com", IsMfaCapable: false},
			{UserPrincipalName: "user3@test.com", IsMfaCapable: true},
			{UserPrincipalName: "user4@test.com", IsMfaCapable: false},
		},
	}

	result, err := checkUsersAreMFACapable(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when some users are not MFA capable")
	}
	if result.Evidence == nil {
		t.Fatal("expected evidence to be non-nil")
	}
	totalNonMFA, ok := result.Evidence["total_non_mfa_capable"].(int)
	if !ok {
		t.Fatal("expected total_non_mfa_capable in evidence")
	}
	if totalNonMFA != 2 {
		t.Errorf("expected 2 non-MFA-capable users in evidence, got %d", totalNonMFA)
	}
}

// ---------------------------------------------------------------------------
// checkSMSVoiceAuthDisabled edge cases
// ---------------------------------------------------------------------------

func TestCheckSMSVoiceAuthDisabled_EmptyMethodConfigs(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthMethodsPolicy: &databag.AuthMethodsPolicy{
			AuthMethodConfigs: []databag.AuthMethodConfiguration{},
		},
	}

	result, err := checkSMSVoiceAuthDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when no auth method configs exist (no weak methods), got: %s", result.Message)
	}
}

func TestCheckSMSVoiceAuthDisabled_OnlyOtherMethods(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthMethodsPolicy: &databag.AuthMethodsPolicy{
			AuthMethodConfigs: []databag.AuthMethodConfiguration{
				{MethodType: "email", State: "enabled"},
				{MethodType: "fido2", State: "enabled"},
			},
		},
	}

	result, err := checkSMSVoiceAuthDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when only email and fido2 methods are configured, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// checkCACoversAllCloudApps edge cases
// ---------------------------------------------------------------------------

func TestCheckCACoversAllCloudApps_BlockPolicyCoversAll(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConditionalAccessPolicies: []databag.ConditionalAccessPolicy{
			{
				ID:                  "policy-1",
				DisplayName:         "Block all apps",
				State:               "enabled",
				IncludeApplications: []string{"All"},
				BuiltInControls:     []string{"block"},
			},
		},
	}

	result, err := checkCACoversAllCloudApps(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The check requires MFA or compliantDevice; "block" alone does not satisfy it
	if result.Passed {
		t.Fatal("expected check to fail when policy only blocks (no MFA or device compliance)")
	}
}

// ---------------------------------------------------------------------------
// checkGuestInvitesRestricted edge cases
// ---------------------------------------------------------------------------

func TestCheckGuestInvitesRestricted_Everyone(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			AllowInvitesFrom: "everyone",
		},
	}

	result, err := checkGuestInvitesRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when AllowInvitesFrom = everyone")
	}
}

func TestCheckGuestInvitesRestricted_None(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			AllowInvitesFrom: "none",
		},
	}

	result, err := checkGuestInvitesRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when AllowInvitesFrom = none, got: %s", result.Message)
	}
}
