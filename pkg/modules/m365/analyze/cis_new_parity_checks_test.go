package analyze

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

// ============================================================================
// Admin Center checks
// ============================================================================

func TestCheckIdleSessionTimeout_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:             "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{IdleSessionTimeout: 120},
	}
	result, err := checkIdleSessionTimeout(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckIdleSessionTimeout_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:             "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{IdleSessionTimeout: 240},
	}
	result, err := checkIdleSessionTimeout(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail for timeout > 180")
	}
}

func TestCheckIdleSessionTimeout_Fail_Zero(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:             "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{IdleSessionTimeout: 0},
	}
	result, err := checkIdleSessionTimeout(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail for timeout == 0 (not configured)")
	}
}

func TestCheckUserOwnedAppsRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:             "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{UserOwnedAppsEnabled: false},
	}
	result, err := checkUserOwnedAppsRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckUserOwnedAppsRestricted_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:             "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{UserOwnedAppsEnabled: true},
	}
	result, err := checkUserOwnedAppsRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckFormsPhishingProtection_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:      "test-tenant",
		FormsSettings: &databag.FormsSettings{InternalPhishingProtection: true},
	}
	result, err := checkFormsPhishingProtection(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckFormsPhishingProtection_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:      "test-tenant",
		FormsSettings: &databag.FormsSettings{InternalPhishingProtection: false},
	}
	result, err := checkFormsPhishingProtection(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckThirdPartyStorageRestrictedM365_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:             "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{ThirdPartyStorageRestricted: true},
	}
	result, err := checkThirdPartyStorageRestrictedM365(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckThirdPartyStorageRestrictedM365_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:             "test-tenant",
		OrganizationSettings: &databag.OrganizationSettings{ThirdPartyStorageRestricted: false},
	}
	result, err := checkThirdPartyStorageRestrictedM365(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckSharedBookingsRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		BookingsSettings: &databag.BookingsSettings{SharedBookingsRestricted: true},
	}
	result, err := checkSharedBookingsRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckSharedBookingsRestricted_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		BookingsSettings: &databag.BookingsSettings{SharedBookingsRestricted: false},
	}
	result, err := checkSharedBookingsRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

// ============================================================================
// Defender checks
// ============================================================================

func TestCheckMalwareInternalNotifications_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MalwareFilterPolicy: []databag.MalwareFilterPolicy{
			{Name: "Default", IsEnabled: true, EnableInternalSenderAdminNotifications: true},
		},
	}
	result, err := checkMalwareInternalNotifications(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckMalwareInternalNotifications_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MalwareFilterPolicy: []databag.MalwareFilterPolicy{
			{Name: "Default", IsEnabled: true, EnableInternalSenderAdminNotifications: false},
		},
	}
	result, err := checkMalwareInternalNotifications(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckSpamNotifyAdmins_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:               "test-tenant",
		SpamNotificationPolicy: &databag.SpamNotificationPolicy{NotifyAdmins: true},
	}
	result, err := checkSpamNotifyAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckSpamNotifyAdmins_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:               "test-tenant",
		SpamNotificationPolicy: &databag.SpamNotificationPolicy{NotifyAdmins: false},
	}
	result, err := checkSpamNotifyAdmins(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckSPFRecords_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DomainSPFRecords: []databag.DomainSPFRecord{
			{Domain: "example.com", HasSPF: true},
		},
	}
	result, err := checkSPFRecords(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckSPFRecords_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DomainSPFRecords: []databag.DomainSPFRecord{
			{Domain: "example.com", HasSPF: false},
		},
	}
	result, err := checkSPFRecords(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckDMARCRecords_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DomainDMARCRecords: []databag.DomainDMARCRecord{
			{Domain: "example.com", HasDMARC: true},
		},
	}
	result, err := checkDMARCRecords(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckDMARCRecords_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DomainDMARCRecords: []databag.DomainDMARCRecord{
			{Domain: "example.com", HasDMARC: false},
		},
	}
	result, err := checkDMARCRecords(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

// ============================================================================
// Purview checks
// ============================================================================

func TestCheckDLPForTeams_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DLPPolicies: []databag.DLPPolicy{
			{IsEnabled: true, TeamsEnabled: true},
		},
	}
	result, err := checkDLPForTeams(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckDLPForTeams_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DLPPolicies: []databag.DLPPolicy{
			{IsEnabled: true, TeamsEnabled: false},
		},
	}
	result, err := checkDLPForTeams(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckSensitivityLabelsPublished_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SensitivityLabels: []databag.SensitivityLabel{
			{Published: true},
		},
	}
	result, err := checkSensitivityLabelsPublished(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckSensitivityLabelsPublished_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SensitivityLabels: []databag.SensitivityLabel{
			{Published: false},
		},
	}
	result, err := checkSensitivityLabelsPublished(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

// ============================================================================
// Intune checks
// ============================================================================

func TestCheckIntuneDevicesNonCompliant_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:               "test-tenant",
		IntuneDeviceCompliance: &databag.IntuneDeviceComplianceSettings{MarkDevicesNonCompliant: true},
	}
	result, err := checkIntuneDevicesNonCompliant(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckIntuneDevicesNonCompliant_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:               "test-tenant",
		IntuneDeviceCompliance: &databag.IntuneDeviceComplianceSettings{MarkDevicesNonCompliant: false},
	}
	result, err := checkIntuneDevicesNonCompliant(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckIntunePersonalEnrollmentBlocked_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                    "test-tenant",
		IntuneEnrollmentRestriction: &databag.IntuneEnrollmentRestriction{PersonalDeviceEnrollmentBlocked: true},
	}
	result, err := checkIntunePersonalEnrollmentBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckIntunePersonalEnrollmentBlocked_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                    "test-tenant",
		IntuneEnrollmentRestriction: &databag.IntuneEnrollmentRestriction{PersonalDeviceEnrollmentBlocked: false},
	}
	result, err := checkIntunePersonalEnrollmentBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

// ============================================================================
// Entra checks
// ============================================================================

func TestCheckThirdPartyIntegratedAppsBlocked_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToCreateApps: false,
			},
		},
	}
	result, err := checkThirdPartyIntegratedAppsBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckThirdPartyIntegratedAppsBlocked_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToCreateApps: true,
			},
		},
	}
	result, err := checkThirdPartyIntegratedAppsBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckUsersCannotCreateSecurityGroups_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToCreateSecurityGroups: false,
			},
		},
	}
	result, err := checkUsersCannotCreateSecurityGroups(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckUsersCannotCreateSecurityGroups_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToCreateSecurityGroups: true,
			},
		},
	}
	result, err := checkUsersCannotCreateSecurityGroups(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckDeviceJoinRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                 "test-tenant",
		DeviceRegistrationPolicy: &databag.DeviceRegistrationPolicy{AllUsersCanJoin: false},
	}
	result, err := checkDeviceJoinRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckDeviceJoinRestricted_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                 "test-tenant",
		DeviceRegistrationPolicy: &databag.DeviceRegistrationPolicy{AllUsersCanJoin: true},
	}
	result, err := checkDeviceJoinRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckMaxDevicesPerUser_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                 "test-tenant",
		DeviceRegistrationPolicy: &databag.DeviceRegistrationPolicy{MaxDevicesPerUser: 10},
	}
	result, err := checkMaxDevicesPerUser(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckMaxDevicesPerUser_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                 "test-tenant",
		DeviceRegistrationPolicy: &databag.DeviceRegistrationPolicy{MaxDevicesPerUser: 0},
	}
	result, err := checkMaxDevicesPerUser(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail for unlimited devices")
	}
}

func TestCheckGANotLocalAdmin_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                 "test-tenant",
		DeviceRegistrationPolicy: &databag.DeviceRegistrationPolicy{GlobalAdminAsLocalAdmin: false},
	}
	result, err := checkGANotLocalAdmin(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckGANotLocalAdmin_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                 "test-tenant",
		DeviceRegistrationPolicy: &databag.DeviceRegistrationPolicy{GlobalAdminAsLocalAdmin: true},
	}
	result, err := checkGANotLocalAdmin(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckAdditionalLocalAdminsLimited_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                 "test-tenant",
		DeviceRegistrationPolicy: &databag.DeviceRegistrationPolicy{AdditionalLocalAdmins: false},
	}
	result, err := checkAdditionalLocalAdminsLimited(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckAdditionalLocalAdminsLimited_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:                 "test-tenant",
		DeviceRegistrationPolicy: &databag.DeviceRegistrationPolicy{AdditionalLocalAdmins: true},
	}
	result, err := checkAdditionalLocalAdminsLimited(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckLAPSEnabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:     "test-tenant",
		LAPSSettings: &databag.LAPSSettings{Enabled: true},
	}
	result, err := checkLAPSEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckLAPSEnabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:     "test-tenant",
		LAPSSettings: &databag.LAPSSettings{Enabled: false},
	}
	result, err := checkLAPSEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckBitlockerKeyRecoveryRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToReadBitlockerKeysForOwnedDevice: false,
			},
		},
	}
	result, err := checkBitlockerKeyRecoveryRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckBitlockerKeyRecoveryRestricted_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthorizationPolicy: &databag.AuthorizationPolicy{
			DefaultUserRolePermissions: &databag.DefaultUserRolePermissions{
				AllowedToReadBitlockerKeysForOwnedDevice: true,
			},
		},
	}
	result, err := checkBitlockerKeyRecoveryRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckCustomBannedPasswords_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		PasswordPolicies: &databag.PasswordPolicies{
			BannedPasswordsEnabled: true,
			CustomBannedPasswords:  []string{"password1", "company123"},
		},
	}
	result, err := checkCustomBannedPasswords(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckCustomBannedPasswords_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		PasswordPolicies: &databag.PasswordPolicies{
			BannedPasswordsEnabled: true,
			CustomBannedPasswords:  []string{},
		},
	}
	result, err := checkCustomBannedPasswords(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail for empty custom list")
	}
}

func TestCheckPasswordProtectionOnPrem_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		PasswordPolicies: &databag.PasswordPolicies{
			EnableBannedPasswordCheckOnPrem: true,
		},
	}
	result, err := checkPasswordProtectionOnPrem(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckPasswordProtectionOnPrem_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		PasswordPolicies: &databag.PasswordPolicies{
			EnableBannedPasswordCheckOnPrem: false,
		},
	}
	result, err := checkPasswordProtectionOnPrem(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckWeakAuthMethodsDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthMethodsPolicy: &databag.AuthMethodsPolicy{
			AuthMethodConfigs: []databag.AuthMethodConfiguration{
				{MethodType: "sms", State: "disabled"},
				{MethodType: "voice", State: "disabled"},
				{MethodType: "email", State: "disabled"},
				{MethodType: "fido2", State: "enabled"},
			},
		},
	}
	result, err := checkWeakAuthMethodsDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckWeakAuthMethodsDisabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AuthMethodsPolicy: &databag.AuthMethodsPolicy{
			AuthMethodConfigs: []databag.AuthMethodConfiguration{
				{MethodType: "sms", State: "enabled"},
				{MethodType: "fido2", State: "enabled"},
			},
		},
	}
	result, err := checkWeakAuthMethodsDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail for enabled SMS")
	}
}

func TestCheckAccessReviewsForGuests_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AccessReviews: []databag.AccessReview{
			{Enabled: true, Scope: "Guest"},
		},
	}
	result, err := checkAccessReviewsForGuests(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckAccessReviewsForGuests_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AccessReviews: []databag.AccessReview{
			{Enabled: true, Scope: "Member"},
		},
	}
	result, err := checkAccessReviewsForGuests(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail for non-Guest scope")
	}
}

// ============================================================================
// Exchange checks
// ============================================================================

func TestCheckDirectSendRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:       "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{DirectSendRestricted: true},
	}
	result, err := checkDirectSendRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckDirectSendRestricted_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:       "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{DirectSendRestricted: false},
	}
	result, err := checkDirectSendRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

// ============================================================================
// SharePoint checks
// ============================================================================

func TestCheckOneDriveSharingRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{OneDriveSharingCapability: "ExternalUserSharingOnly"},
	}
	result, err := checkOneDriveSharingRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckOneDriveSharingRestricted_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{OneDriveSharingCapability: "ExternalUserAndGuestSharing"},
	}
	result, err := checkOneDriveSharingRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckGuestsCannotReshareItems_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{RequireAcceptingAccountMatchInvitedAccount: true},
	}
	result, err := checkGuestsCannotReshareItems(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckGuestsCannotReshareItems_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{RequireAcceptingAccountMatchInvitedAccount: false},
	}
	result, err := checkGuestsCannotReshareItems(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckLinkSharingRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{DefaultSharingLinkType: "Internal"},
	}
	result, err := checkLinkSharingRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckLinkSharingRestricted_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{DefaultSharingLinkType: "AnonymousAccess"},
	}
	result, err := checkLinkSharingRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckGuestAccessExpires_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{ExternalUserExpireInDays: 30},
	}
	result, err := checkGuestAccessExpires(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckGuestAccessExpires_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{ExternalUserExpireInDays: 0},
	}
	result, err := checkGuestAccessExpires(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail for no expiration")
	}
}

func TestCheckReauthVerificationCode_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{EmailAttestationReAuthDays: 15},
	}
	result, err := checkReauthVerificationCode(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckReauthVerificationCode_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{EmailAttestationReAuthDays: 0},
	}
	result, err := checkReauthVerificationCode(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail for not configured")
	}
}

func TestCheckDefaultLinkPermissionView_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{DefaultLinkPermission: "View"},
	}
	result, err := checkDefaultLinkPermissionView(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckDefaultLinkPermissionView_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{DefaultLinkPermission: "Edit"},
	}
	result, err := checkDefaultLinkPermissionView(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

func TestCheckInfectedFileDownloadBlocked_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{DisallowInfectedFileDownload: true},
	}
	result, err := checkInfectedFileDownloadBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckInfectedFileDownloadBlocked_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		SharePointTenant: &databag.SharePointTenantConfig{DisallowInfectedFileDownload: false},
	}
	result, err := checkInfectedFileDownloadBlocked(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}

// ============================================================================
// Teams checks
// ============================================================================

func TestCheckTeamsSkypeDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:            "test-tenant",
		TeamsExternalAccess: &databag.TeamsExternalAccessPolicy{AllowPublicUsers: false},
	}
	result, err := checkTeamsSkypeDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Message)
	}
}

func TestCheckTeamsSkypeDisabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:            "test-tenant",
		TeamsExternalAccess: &databag.TeamsExternalAccessPolicy{AllowPublicUsers: true},
	}
	result, err := checkTeamsSkypeDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected fail")
	}
}
