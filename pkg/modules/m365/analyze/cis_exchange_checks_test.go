package analyze

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

// ---------------------------------------------------------------------------
// 6.1.1 - checkOrgMailboxAuditingEnabled
// ---------------------------------------------------------------------------

func TestCheckOrgMailboxAuditingEnabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			AuditDisabled: false,
		},
	}

	result, err := checkOrgMailboxAuditingEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckOrgMailboxAuditingEnabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			AuditDisabled: true,
		},
	}

	result, err := checkOrgMailboxAuditingEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when auditing is disabled")
	}
}

func TestCheckOrgMailboxAuditingEnabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkOrgMailboxAuditingEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil exchange config")
	}
}

// ---------------------------------------------------------------------------
// 6.1.2 - checkUserMailboxAuditingActions
// ---------------------------------------------------------------------------

func TestCheckUserMailboxAuditingActions_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxAuditConfig: []databag.MailboxAuditConfig{
			{
				Identity:     "user@test.com",
				AuditEnabled: true,
				AuditAdmin: []string{
					"ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete",
					"Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf",
					"SoftDelete", "Update", "UpdateCalendarDelegation",
					"UpdateFolderPermissions", "UpdateInboxRules",
				},
				AuditDelegate: []string{
					"ApplyRecord", "Create", "FolderBind", "HardDelete",
					"Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf",
					"SoftDelete", "Update", "UpdateFolderPermissions",
					"UpdateInboxRules",
				},
				AuditOwner: []string{
					"ApplyRecord", "Create", "HardDelete", "MailboxLogin",
					"Move", "MoveToDeletedItems", "SoftDelete", "Update",
					"UpdateCalendarDelegation", "UpdateFolderPermissions",
					"UpdateInboxRules",
				},
			},
		},
	}

	result, err := checkUserMailboxAuditingActions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckUserMailboxAuditingActions_Fail_MissingActions(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxAuditConfig: []databag.MailboxAuditConfig{
			{
				Identity:      "user@test.com",
				AuditEnabled:  true,
				AuditAdmin:    []string{"Create"},
				AuditDelegate: []string{"Create"},
				AuditOwner:    []string{"Create"},
			},
		},
	}

	result, err := checkUserMailboxAuditingActions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with missing audit actions")
	}
}

func TestCheckUserMailboxAuditingActions_Fail_AuditDisabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxAuditConfig: []databag.MailboxAuditConfig{
			{
				Identity:     "user@test.com",
				AuditEnabled: false,
			},
		},
	}

	result, err := checkUserMailboxAuditingActions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when auditing is disabled on mailbox")
	}
}

func TestCheckUserMailboxAuditingActions_Fail_NoConfigs(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkUserMailboxAuditingActions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no mailbox audit configs")
	}
}

// ---------------------------------------------------------------------------
// 6.1.3 - checkAuditBypassDisabled
// ---------------------------------------------------------------------------

func TestCheckAuditBypassDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxAuditConfig: []databag.MailboxAuditConfig{
			{Identity: "user1@test.com", AuditBypassEnabled: false},
			{Identity: "user2@test.com", AuditBypassEnabled: false},
		},
	}

	result, err := checkAuditBypassDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckAuditBypassDisabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxAuditConfig: []databag.MailboxAuditConfig{
			{Identity: "user1@test.com", AuditBypassEnabled: false},
			{Identity: "service@test.com", AuditBypassEnabled: true},
		},
	}

	result, err := checkAuditBypassDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when audit bypass is enabled")
	}
}

func TestCheckAuditBypassDisabled_Fail_NoConfigs(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkAuditBypassDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no configs")
	}
}

// ---------------------------------------------------------------------------
// 6.2.1 - checkNoTransportRuleForwardingExternal
// ---------------------------------------------------------------------------

func TestCheckNoTransportRuleForwardingExternal_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{
				Name:  "Tag External",
				State: "Enabled",
			},
		},
	}

	result, err := checkNoTransportRuleForwardingExternal(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckNoTransportRuleForwardingExternal_Pass_NoRules(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkNoTransportRuleForwardingExternal(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with no rules, got: %s", result.Message)
	}
}

func TestCheckNoTransportRuleForwardingExternal_Fail_Redirect(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{
				Name:              "Forward to external",
				State:             "Enabled",
				RedirectMessageTo: []string{"external@example.com"},
			},
		},
	}

	result, err := checkNoTransportRuleForwardingExternal(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with forwarding transport rule")
	}
}

func TestCheckNoTransportRuleForwardingExternal_Fail_OutboundConnector(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{
				Name:                          "Route to connector",
				State:                         "Enabled",
				RouteMessageOutboundConnector: "ExternalConnector",
			},
		},
	}

	result, err := checkNoTransportRuleForwardingExternal(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with outbound connector route")
	}
}

func TestCheckNoTransportRuleForwardingExternal_Pass_DisabledRule(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{
				Name:              "Disabled forwarding rule",
				State:             "Disabled",
				RedirectMessageTo: []string{"external@example.com"},
			},
		},
	}

	result, err := checkNoTransportRuleForwardingExternal(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass for disabled rule, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// 6.2.2 - checkNoDomainWhitelistTransportRules
// ---------------------------------------------------------------------------

func TestCheckNoDomainWhitelistTransportRules_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{Name: "Normal Rule", State: "Enabled"},
		},
	}

	result, err := checkNoDomainWhitelistTransportRules(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckNoDomainWhitelistTransportRules_Fail_Whitelisted(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{
				Name:                      "Whitelist Rule",
				State:                     "Enabled",
				SenderDomainIsWhitelisted: true,
			},
		},
	}

	result, err := checkNoDomainWhitelistTransportRules(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with whitelisted domain rule")
	}
}

func TestCheckNoDomainWhitelistTransportRules_Fail_SCLMinus1(t *testing.T) {
	scl := -1
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{
				Name:   "SCL -1 Rule",
				State:  "Enabled",
				SetSCL: &scl,
			},
		},
	}

	result, err := checkNoDomainWhitelistTransportRules(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with SCL=-1 rule")
	}
}

// ---------------------------------------------------------------------------
// 6.2.3 - checkExternalEmailTaggingEnabled
// ---------------------------------------------------------------------------

func TestCheckExternalEmailTaggingEnabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExternalEmailTagging: &databag.ExternalEmailTagging{
			Enabled: true,
		},
	}

	result, err := checkExternalEmailTaggingEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckExternalEmailTaggingEnabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExternalEmailTagging: &databag.ExternalEmailTagging{
			Enabled: false,
		},
	}

	result, err := checkExternalEmailTaggingEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when tagging is disabled")
	}
}

func TestCheckExternalEmailTaggingEnabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkExternalEmailTaggingEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil config")
	}
}

// ---------------------------------------------------------------------------
// 6.3.1 - checkOutlookAddInsDisabled
// ---------------------------------------------------------------------------

func TestCheckOutlookAddInsDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		RoleAssignmentPolicies: []databag.RoleAssignmentPolicy{
			{
				Name:          "Default Role Assignment",
				AssignedRoles: []string{"MyBaseOptions", "MyContactInformation"},
			},
		},
	}

	result, err := checkOutlookAddInsDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckOutlookAddInsDisabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		RoleAssignmentPolicies: []databag.RoleAssignmentPolicy{
			{
				Name:          "Default Role Assignment",
				AssignedRoles: []string{"My Custom Apps", "My Marketplace Apps"},
			},
		},
	}

	result, err := checkOutlookAddInsDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when add-in roles are assigned")
	}
}

func TestCheckOutlookAddInsDisabled_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkOutlookAddInsDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ---------------------------------------------------------------------------
// 6.5.1 - checkModernAuthEnabled
// ---------------------------------------------------------------------------

func TestCheckModernAuthEnabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			ModernAuthEnabled: true,
		},
	}

	result, err := checkModernAuthEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckModernAuthEnabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			ModernAuthEnabled: false,
		},
	}

	result, err := checkModernAuthEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when modern auth is disabled")
	}
}

func TestCheckModernAuthEnabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkModernAuthEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil exchange config")
	}
}

// ---------------------------------------------------------------------------
// 6.5.2 - checkMailTipsFullyEnabled
// ---------------------------------------------------------------------------

func TestCheckMailTipsFullyEnabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			MailTipsAllTipsEnabled:                true,
			MailTipsExternalRecipientsTipsEnabled: true,
			MailTipsGroupMetricsEnabled:           true,
			MailTipsLargeAudienceThreshold:        25,
		},
	}

	result, err := checkMailTipsFullyEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckMailTipsFullyEnabled_Fail_TipsDisabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			MailTipsAllTipsEnabled:                false,
			MailTipsExternalRecipientsTipsEnabled: true,
			MailTipsGroupMetricsEnabled:           true,
			MailTipsLargeAudienceThreshold:        25,
		},
	}

	result, err := checkMailTipsFullyEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when all tips are disabled")
	}
}

func TestCheckMailTipsFullyEnabled_Fail_ZeroThreshold(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			MailTipsAllTipsEnabled:                true,
			MailTipsExternalRecipientsTipsEnabled: true,
			MailTipsGroupMetricsEnabled:           true,
			MailTipsLargeAudienceThreshold:        0,
		},
	}

	result, err := checkMailTipsFullyEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with zero audience threshold")
	}
}

// ---------------------------------------------------------------------------
// 6.5.3 - checkThirdPartyStorageDisabled
// ---------------------------------------------------------------------------

func TestCheckThirdPartyStorageDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxPolicies: []databag.MailboxPolicy{
			{
				Name:                                "OwaMailboxPolicy-Default",
				ThirdPartyFileProvidersEnabled:      false,
				AdditionalStorageProvidersAvailable: false,
			},
		},
	}

	result, err := checkThirdPartyStorageDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckThirdPartyStorageDisabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxPolicies: []databag.MailboxPolicy{
			{
				Name:                                "OwaMailboxPolicy-Default",
				ThirdPartyFileProvidersEnabled:      true,
				AdditionalStorageProvidersAvailable: false,
			},
		},
	}

	result, err := checkThirdPartyStorageDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when third-party providers are enabled")
	}
}

func TestCheckThirdPartyStorageDisabled_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkThirdPartyStorageDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ---------------------------------------------------------------------------
// 6.5.4 - checkSMTPAuthDisabledGlobally
// ---------------------------------------------------------------------------

func TestCheckSMTPAuthDisabledGlobally_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			SmtpClientAuthenticationDisabled: true,
		},
	}

	result, err := checkSMTPAuthDisabledGlobally(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSMTPAuthDisabledGlobally_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			SmtpClientAuthenticationDisabled: false,
		},
	}

	result, err := checkSMTPAuthDisabledGlobally(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when SMTP AUTH is not disabled")
	}
}

func TestCheckSMTPAuthDisabledGlobally_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkSMTPAuthDisabledGlobally(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil exchange config")
	}
}

// ---------------------------------------------------------------------------
// 1.2.2 - checkSharedMailboxSignInDisabled
// ---------------------------------------------------------------------------

func TestCheckSharedMailboxSignInDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharedMailboxes: []databag.SharedMailbox{
			{Identity: "shared1@test.com", SignInEnabled: false, AccountEnabled: false},
			{Identity: "shared2@test.com", SignInEnabled: false, AccountEnabled: false},
		},
	}

	result, err := checkSharedMailboxSignInDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSharedMailboxSignInDisabled_Pass_NoMailboxes(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkSharedMailboxSignInDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with no shared mailboxes, got: %s", result.Message)
	}
}

func TestCheckSharedMailboxSignInDisabled_Fail_SignInEnabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharedMailboxes: []databag.SharedMailbox{
			{Identity: "shared@test.com", SignInEnabled: true, AccountEnabled: false},
		},
	}

	result, err := checkSharedMailboxSignInDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when sign-in is enabled on shared mailbox")
	}
}

func TestCheckSharedMailboxSignInDisabled_Fail_AccountEnabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharedMailboxes: []databag.SharedMailbox{
			{Identity: "shared@test.com", SignInEnabled: false, AccountEnabled: true},
		},
	}

	result, err := checkSharedMailboxSignInDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when account is enabled on shared mailbox")
	}
}

// ---------------------------------------------------------------------------
// Edge-case and negative tests
// ---------------------------------------------------------------------------

func TestCheckUserMailboxAudit_EmptyAuditActions(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxAuditConfig: []databag.MailboxAuditConfig{
			{
				Identity:     "user@test.com",
				AuditEnabled: true,
				AuditAdmin: []string{
					"ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete",
					"Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf",
					"SoftDelete", "Update", "UpdateCalendarDelegation",
					"UpdateFolderPermissions", "UpdateInboxRules",
				},
				AuditDelegate: []string{},
				AuditOwner:    []string{},
			},
		},
	}

	result, err := checkUserMailboxAuditingActions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when AuditDelegate and AuditOwner are empty")
	}
}

func TestCheckUserMailboxAudit_MultipleMailboxes(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxAuditConfig: []databag.MailboxAuditConfig{
			{
				Identity:     "compliant@test.com",
				AuditEnabled: true,
				AuditAdmin: []string{
					"ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete",
					"Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf",
					"SoftDelete", "Update", "UpdateCalendarDelegation",
					"UpdateFolderPermissions", "UpdateInboxRules",
				},
				AuditDelegate: []string{
					"ApplyRecord", "Create", "FolderBind", "HardDelete",
					"Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf",
					"SoftDelete", "Update", "UpdateFolderPermissions",
					"UpdateInboxRules",
				},
				AuditOwner: []string{
					"ApplyRecord", "Create", "HardDelete", "MailboxLogin",
					"Move", "MoveToDeletedItems", "SoftDelete", "Update",
					"UpdateCalendarDelegation", "UpdateFolderPermissions",
					"UpdateInboxRules",
				},
			},
			{
				Identity:      "noncompliant@test.com",
				AuditEnabled:  true,
				AuditAdmin:    []string{"Create"},
				AuditDelegate: []string{"Create"},
				AuditOwner:    []string{"Create"},
			},
		},
	}

	result, err := checkUserMailboxAuditingActions(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when one of multiple mailboxes is non-compliant")
	}
}

func TestCheckAuditBypass_AllEnabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxAuditConfig: []databag.MailboxAuditConfig{
			{Identity: "user1@test.com", AuditBypassEnabled: true},
			{Identity: "user2@test.com", AuditBypassEnabled: true},
			{Identity: "user3@test.com", AuditBypassEnabled: true},
		},
	}

	result, err := checkAuditBypassDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when all mailboxes have bypass enabled")
	}
}

func TestCheckAuditBypass_EmptyMailboxes(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:           "test-tenant",
		MailboxAuditConfig: []databag.MailboxAuditConfig{},
	}

	result, err := checkAuditBypassDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty MailboxAuditConfig slice")
	}
}

func TestCheckTransportForwarding_BothRedirectAndConnector(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{
				Name:                          "Double forward",
				State:                         "Enabled",
				RedirectMessageTo:             []string{"external@example.com"},
				RouteMessageOutboundConnector: "ExternalConnector",
			},
		},
	}

	result, err := checkNoTransportRuleForwardingExternal(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when rule has both redirect and outbound connector")
	}
}

func TestCheckTransportForwarding_MultipleRulesOneForwarding(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{
				Name:  "Safe Rule",
				State: "Enabled",
			},
			{
				Name:              "Forwarding Rule",
				State:             "Enabled",
				RedirectMessageTo: []string{"external@example.com"},
			},
			{
				Name:  "Another Safe Rule",
				State: "Enabled",
			},
		},
	}

	result, err := checkNoTransportRuleForwardingExternal(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when one of multiple rules has forwarding")
	}
}

func TestCheckDomainWhitelist_NilSCL(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{
				Name:   "Rule with nil SCL",
				State:  "Enabled",
				SetSCL: nil,
			},
		},
	}

	result, err := checkNoDomainWhitelistTransportRules(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with nil SCL, got: %s", result.Message)
	}
}

func TestCheckDomainWhitelist_ZeroSCL(t *testing.T) {
	scl := 0
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TransportRules: []databag.TransportRule{
			{
				Name:   "Rule with zero SCL",
				State:  "Enabled",
				SetSCL: &scl,
			},
		},
	}

	result, err := checkNoDomainWhitelistTransportRules(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with SCL=0, got: %s", result.Message)
	}
}

func TestCheckOutlookAddIns_MixedRoles(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		RoleAssignmentPolicies: []databag.RoleAssignmentPolicy{
			{
				Name:          "Mixed Policy",
				AssignedRoles: []string{"MyBaseOptions", "My Custom Apps", "MyContactInformation"},
			},
		},
	}

	result, err := checkOutlookAddInsDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when policy has both add-in and non-add-in roles")
	}
}

func TestCheckOutlookAddIns_EmptyPolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:               "test-tenant",
		RoleAssignmentPolicies: []databag.RoleAssignmentPolicy{},
	}

	result, err := checkOutlookAddInsDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty RoleAssignmentPolicies slice")
	}
}

func TestCheckMailTips_PartialEnabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			MailTipsAllTipsEnabled:                true,
			MailTipsExternalRecipientsTipsEnabled: false,
			MailTipsGroupMetricsEnabled:           true,
			MailTipsLargeAudienceThreshold:        25,
		},
	}

	result, err := checkMailTipsFullyEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when AllTips=true but External=false")
	}
}

func TestCheckMailTips_Boundary_ThresholdOne(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExchangeConfig: &databag.ExchangeOrgConfig{
			MailTipsAllTipsEnabled:                true,
			MailTipsExternalRecipientsTipsEnabled: true,
			MailTipsGroupMetricsEnabled:           true,
			MailTipsLargeAudienceThreshold:        1,
		},
	}

	result, err := checkMailTipsFullyEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with threshold=1, got: %s", result.Message)
	}
}

func TestCheckThirdPartyStorage_OnlyOneDisabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MailboxPolicies: []databag.MailboxPolicy{
			{
				Name:                                "OwaMailboxPolicy-Default",
				ThirdPartyFileProvidersEnabled:      false,
				AdditionalStorageProvidersAvailable: true,
			},
		},
	}

	result, err := checkThirdPartyStorageDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when ThirdPartyFileProvidersEnabled=false but AdditionalStorageProvidersAvailable=true")
	}
}

func TestCheckSharedMailbox_MixedMailboxes(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SharedMailboxes: []databag.SharedMailbox{
			{Identity: "compliant@test.com", SignInEnabled: false, AccountEnabled: false},
			{Identity: "noncompliant@test.com", SignInEnabled: true, AccountEnabled: false},
			{Identity: "also-compliant@test.com", SignInEnabled: false, AccountEnabled: false},
		},
	}

	result, err := checkSharedMailboxSignInDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when some shared mailboxes have sign-in enabled")
	}
}

func TestCheckSharedMailbox_EmptyList(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:        "test-tenant",
		SharedMailboxes: []databag.SharedMailbox{},
	}

	result, err := checkSharedMailboxSignInDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with empty SharedMailboxes slice, got: %s", result.Message)
	}
}
