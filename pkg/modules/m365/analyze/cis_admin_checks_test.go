package analyze

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

// ---------------------------------------------------------------------------
// 1.1.4 - checkAdminReducedLicenses
// ---------------------------------------------------------------------------

func TestCheckAdminReducedLicenses_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"admin-1"},
			},
		},
		Users: []databag.User{
			{
				ID:                "admin-1",
				UserPrincipalName: "admin@test.com",
				AssignedLicenses:  []string{"license-1"},
			},
		},
	}

	result, err := checkAdminReducedLicenses(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckAdminReducedLicenses_Pass_NoAdmins(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkAdminReducedLicenses(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with no admins, got: %s", result.Message)
	}
}

func TestCheckAdminReducedLicenses_Fail_TooManyLicenses(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"admin-1"},
			},
		},
		Users: []databag.User{
			{
				ID:                "admin-1",
				UserPrincipalName: "admin@test.com",
				AssignedLicenses:  []string{"lic-1", "lic-2", "lic-3"},
			},
		},
	}

	result, err := checkAdminReducedLicenses(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when admin has more than 2 licenses")
	}
}

func TestCheckAdminReducedLicenses_Pass_ExactlyTwo(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"admin-1"},
			},
		},
		Users: []databag.User{
			{
				ID:                "admin-1",
				UserPrincipalName: "admin@test.com",
				AssignedLicenses:  []string{"lic-1", "lic-2"},
			},
		},
	}

	result, err := checkAdminReducedLicenses(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with exactly 2 licenses, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// 1.2.1 - checkM365GroupsPrivate
// ---------------------------------------------------------------------------

func TestCheckM365GroupsPrivate_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Groups: []databag.Group{
			{
				ID:          "group-1",
				DisplayName: "Engineering",
				GroupTypes:  []string{"Unified"},
				Visibility:  "Private",
			},
		},
	}

	result, err := checkM365GroupsPrivate(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckM365GroupsPrivate_Pass_NoUnifiedGroups(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Groups: []databag.Group{
			{
				ID:          "group-1",
				DisplayName: "Security Group",
				GroupTypes:  []string{"Security"},
				Visibility:  "Public",
			},
		},
	}

	result, err := checkM365GroupsPrivate(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass for non-Unified groups, got: %s", result.Message)
	}
}

func TestCheckM365GroupsPrivate_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Groups: []databag.Group{
			{
				ID:          "group-1",
				DisplayName: "Public Group",
				GroupTypes:  []string{"Unified"},
				Visibility:  "Public",
			},
		},
	}

	result, err := checkM365GroupsPrivate(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when a Unified group is Public")
	}
}

func TestCheckM365GroupsPrivate_Pass_Empty(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkM365GroupsPrivate(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with no groups, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// 1.3.1 - checkPasswordNeverExpire
// ---------------------------------------------------------------------------

func TestCheckPasswordNeverExpire_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{
			PasswordNeverExpires: true,
		},
	}

	result, err := checkPasswordNeverExpire(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckPasswordNeverExpire_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{
			PasswordNeverExpires:   false,
			PasswordExpirationDays: 90,
		},
	}

	result, err := checkPasswordNeverExpire(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when password expiration is configured")
	}
}

func TestCheckPasswordNeverExpire_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkPasswordNeverExpire(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil organization settings")
	}
}

// ---------------------------------------------------------------------------
// 1.3.3 - checkExternalCalendarSharingDisabled
// ---------------------------------------------------------------------------

func TestCheckExternalCalendarSharingDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{
			CalendarSharingExternal: false,
		},
	}

	result, err := checkExternalCalendarSharingDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckExternalCalendarSharingDisabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{
			CalendarSharingExternal: true,
		},
	}

	result, err := checkExternalCalendarSharingDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when external calendar sharing is enabled")
	}
}

func TestCheckExternalCalendarSharingDisabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkExternalCalendarSharingDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil organization settings")
	}
}

// ---------------------------------------------------------------------------
// 1.3.6 - checkCustomerLockboxEnabled
// ---------------------------------------------------------------------------

func TestCheckCustomerLockboxEnabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{
			CustomerLockboxEnabled: true,
		},
	}

	result, err := checkCustomerLockboxEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckCustomerLockboxEnabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{
			CustomerLockboxEnabled: false,
		},
	}

	result, err := checkCustomerLockboxEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when Customer Lockbox is disabled")
	}
}

func TestCheckCustomerLockboxEnabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkCustomerLockboxEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil organization settings")
	}
}

// ---------------------------------------------------------------------------
// Edge-case and negative tests
// ---------------------------------------------------------------------------

func TestCheckAdminReducedLicenses_NoUsers(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"admin-1"},
			},
		},
		Users: []databag.User{},
	}

	result, err := checkAdminReducedLicenses(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when admin roles exist but Users array is empty, got: %s", result.Message)
	}
}

func TestCheckAdminReducedLicenses_AdminWithZeroLicenses(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"admin-1"},
			},
		},
		Users: []databag.User{
			{
				ID:                "admin-1",
				UserPrincipalName: "admin@test.com",
				AssignedLicenses:  []string{},
			},
		},
	}

	result, err := checkAdminReducedLicenses(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when admin has 0 licenses, got: %s", result.Message)
	}
}

func TestCheckAdminReducedLicenses_AdminIDNotInUsers(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DirectoryRoles: []databag.DirectoryRole{
			{
				RoleTemplateID: "62e90394-69f5-4237-9190-012177145e10",
				Members:        []string{"admin-999"},
			},
		},
		Users: []databag.User{
			{
				ID:                "regular-1",
				UserPrincipalName: "user@test.com",
				AssignedLicenses:  []string{"lic-1", "lic-2", "lic-3", "lic-4"},
			},
		},
	}

	result, err := checkAdminReducedLicenses(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when admin member ID does not match any user, got: %s", result.Message)
	}
}

func TestCheckM365GroupsPrivate_MixedGroups(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Groups: []databag.Group{
			{
				ID:          "group-1",
				DisplayName: "Private Engineering",
				GroupTypes:  []string{"Unified"},
				Visibility:  "Private",
			},
			{
				ID:          "group-2",
				DisplayName: "Public Marketing",
				GroupTypes:  []string{"Unified"},
				Visibility:  "Public",
			},
		},
	}

	result, err := checkM365GroupsPrivate(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when some Unified groups are public")
	}
}

func TestCheckM365GroupsPrivate_NonUnifiedPublic(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Groups: []databag.Group{
			{
				ID:          "group-1",
				DisplayName: "Public Security Group",
				GroupTypes:  []string{"Security"},
				Visibility:  "Public",
			},
		},
	}

	result, err := checkM365GroupsPrivate(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass for non-Unified public group, got: %s", result.Message)
	}
}

func TestCheckM365GroupsPrivate_EmptyGroupTypes(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		Groups: []databag.Group{
			{
				ID:          "group-1",
				DisplayName: "Empty Types Group",
				GroupTypes:  []string{},
				Visibility:  "Public",
			},
		},
	}

	result, err := checkM365GroupsPrivate(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass for group with empty GroupTypes, got: %s", result.Message)
	}
}

func TestCheckPasswordNeverExpire_ZeroDays(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{
			PasswordNeverExpires:   false,
			PasswordExpirationDays: 0,
		},
	}

	result, err := checkPasswordNeverExpire(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when PasswordNeverExpires=false even with PasswordExpirationDays=0")
	}
}
