package analyze

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

// ---------------------------------------------------------------------------
// 7.2.1 - checkSharePointModernAuth
// ---------------------------------------------------------------------------

func TestCheckSharePointModernAuth_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			LegacyAuthProtocolsEnabled: false,
		},
	}

	result, err := checkSharePointModernAuth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSharePointModernAuth_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			LegacyAuthProtocolsEnabled: true,
		},
	}

	result, err := checkSharePointModernAuth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when legacy auth is enabled")
	}
}

func TestCheckSharePointModernAuth_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkSharePointModernAuth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil SharePoint tenant config")
	}
}

// ---------------------------------------------------------------------------
// 7.2.2 - checkSharePointGuestsCannotReshare
// ---------------------------------------------------------------------------

func TestCheckSharePointGuestsCannotReshare_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			PreventExternalUsersFromResharing: true,
		},
	}

	result, err := checkSharePointGuestsCannotReshare(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSharePointGuestsCannotReshare_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			PreventExternalUsersFromResharing: false,
		},
	}

	result, err := checkSharePointGuestsCannotReshare(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when guests can reshare")
	}
}

func TestCheckSharePointGuestsCannotReshare_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkSharePointGuestsCannotReshare(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil SharePoint tenant config")
	}
}

// ---------------------------------------------------------------------------
// 7.2.3 - checkSharePointDomainRestrictions
// ---------------------------------------------------------------------------

func TestCheckSharePointDomainRestrictions_Pass_AllowList(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingDomainRestrictionMode: "AllowList",
		},
	}

	result, err := checkSharePointDomainRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSharePointDomainRestrictions_Pass_BlockList(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingDomainRestrictionMode: "BlockList",
		},
	}

	result, err := checkSharePointDomainRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSharePointDomainRestrictions_Fail_None(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingDomainRestrictionMode: "None",
		},
	}

	result, err := checkSharePointDomainRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with None domain restriction mode")
	}
}

func TestCheckSharePointDomainRestrictions_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkSharePointDomainRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil SharePoint tenant config")
	}
}

// ---------------------------------------------------------------------------
// 7.2.6 - checkSharePointNoAnonymousLinks
// ---------------------------------------------------------------------------

func TestCheckSharePointNoAnonymousLinks_Pass_Disabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingCapability: "Disabled",
		},
	}

	result, err := checkSharePointNoAnonymousLinks(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSharePointNoAnonymousLinks_Pass_ExternalUserSharingOnly(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingCapability: "ExternalUserSharingOnly",
		},
	}

	result, err := checkSharePointNoAnonymousLinks(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSharePointNoAnonymousLinks_Pass_ExistingExternal(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingCapability: "ExistingExternalUserSharingOnly",
		},
	}

	result, err := checkSharePointNoAnonymousLinks(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSharePointNoAnonymousLinks_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingCapability: "ExternalUserAndGuestSharing",
		},
	}

	result, err := checkSharePointNoAnonymousLinks(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when anonymous links are allowed")
	}
}

func TestCheckSharePointNoAnonymousLinks_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkSharePointNoAnonymousLinks(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil SharePoint tenant config")
	}
}

// ---------------------------------------------------------------------------
// 7.3.2 - checkOneDriveSyncBlockedUnmanaged
// ---------------------------------------------------------------------------

func TestCheckOneDriveSyncBlockedUnmanaged_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			IsUnmanagedSyncClientForTenantRestricted: true,
		},
	}

	result, err := checkOneDriveSyncBlockedUnmanaged(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckOneDriveSyncBlockedUnmanaged_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			IsUnmanagedSyncClientForTenantRestricted: false,
		},
	}

	result, err := checkOneDriveSyncBlockedUnmanaged(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when unmanaged sync is not restricted")
	}
}

func TestCheckOneDriveSyncBlockedUnmanaged_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkOneDriveSyncBlockedUnmanaged(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil SharePoint tenant config")
	}
}

// ---------------------------------------------------------------------------
// Edge-case and negative tests
// ---------------------------------------------------------------------------

func TestCheckSharePointDomainRestrictions_EmptyMode(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingDomainRestrictionMode: "",
		},
	}

	result, err := checkSharePointDomainRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty SharingDomainRestrictionMode")
	}
}

func TestCheckSharePointDomainRestrictions_CaseSensitivity(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingDomainRestrictionMode: "allowlist",
		},
	}

	result, err := checkSharePointDomainRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with lowercase 'allowlist', got: %s", result.Message)
	}
}

func TestCheckSharePointDomainRestrictions_UnknownMode(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingDomainRestrictionMode: "CustomMode",
		},
	}

	result, err := checkSharePointDomainRestrictions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with unknown restriction mode")
	}
}

func TestCheckSharePointNoAnonymousLinks_EmptyCapability(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingCapability: "",
		},
	}

	result, err := checkSharePointNoAnonymousLinks(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty SharingCapability")
	}
}

func TestCheckSharePointNoAnonymousLinks_CaseSensitivity(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			SharingCapability: "disabled",
		},
	}

	result, err := checkSharePointNoAnonymousLinks(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with lowercase 'disabled', got: %s", result.Message)
	}
}

func TestCheckSharePointModernAuth_DefaultFalse(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{
			LegacyAuthProtocolsEnabled: false,
		},
	}

	result, err := checkSharePointModernAuth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with LegacyAuthProtocolsEnabled=false, got: %s", result.Message)
	}
}
