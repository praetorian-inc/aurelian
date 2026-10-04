package analyze

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

// ---------------------------------------------------------------------------
// 2.1.1 - checkSafeLinksPolicy
// ---------------------------------------------------------------------------

func TestCheckSafeLinksPolicy_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeLinksPolicy: []databag.SafeLinksPolicy{
			{
				Name:                   "Default Safe Links",
				IsEnabled:              true,
				ScanUrls:               true,
				DoNotAllowClickThrough: true,
				EnableForInternalSenders: true,
			},
		},
	}

	result, err := checkSafeLinksPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSafeLinksPolicy_Fail_NotFullyConfigured(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeLinksPolicy: []databag.SafeLinksPolicy{
			{
				Name:                   "Partial Safe Links",
				IsEnabled:              true,
				ScanUrls:               true,
				DoNotAllowClickThrough: false,
				EnableForInternalSenders: true,
			},
		},
	}

	result, err := checkSafeLinksPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when DoNotAllowClickThrough is false")
	}
}

func TestCheckSafeLinksPolicy_Fail_Disabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeLinksPolicy: []databag.SafeLinksPolicy{
			{
				Name:                   "Disabled Safe Links",
				IsEnabled:              false,
				ScanUrls:               true,
				DoNotAllowClickThrough: true,
				EnableForInternalSenders: true,
			},
		},
	}

	result, err := checkSafeLinksPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when policy is disabled")
	}
}

func TestCheckSafeLinksPolicy_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkSafeLinksPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ---------------------------------------------------------------------------
// 2.1.2 - checkCommonAttachmentFilter
// ---------------------------------------------------------------------------

func TestCheckCommonAttachmentFilter_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MalwareFilterPolicy: []databag.MalwareFilterPolicy{
			{
				Name:             "Default Malware Filter",
				IsEnabled:        true,
				EnableFileFilter: true,
			},
		},
	}

	result, err := checkCommonAttachmentFilter(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckCommonAttachmentFilter_Fail_FilterDisabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MalwareFilterPolicy: []databag.MalwareFilterPolicy{
			{
				Name:             "Default Malware Filter",
				IsEnabled:        true,
				EnableFileFilter: false,
			},
		},
	}

	result, err := checkCommonAttachmentFilter(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when file filter is disabled")
	}
}

func TestCheckCommonAttachmentFilter_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkCommonAttachmentFilter(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ---------------------------------------------------------------------------
// 2.1.4 - checkSafeAttachmentsPolicy
// ---------------------------------------------------------------------------

func TestCheckSafeAttachmentsPolicy_Pass_Block(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeAttachmentPolicy: []databag.SafeAttachmentPolicy{
			{
				Name:      "Block Attachments",
				IsEnabled: true,
				Action:    "Block",
			},
		},
	}

	result, err := checkSafeAttachmentsPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSafeAttachmentsPolicy_Pass_DynamicDelivery(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeAttachmentPolicy: []databag.SafeAttachmentPolicy{
			{
				Name:      "Dynamic Delivery",
				IsEnabled: true,
				Action:    "DynamicDelivery",
			},
		},
	}

	result, err := checkSafeAttachmentsPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckSafeAttachmentsPolicy_Fail_AllowAction(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeAttachmentPolicy: []databag.SafeAttachmentPolicy{
			{
				Name:      "Allow Attachments",
				IsEnabled: true,
				Action:    "Allow",
			},
		},
	}

	result, err := checkSafeAttachmentsPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with Allow action")
	}
}

func TestCheckSafeAttachmentsPolicy_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkSafeAttachmentsPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ---------------------------------------------------------------------------
// 2.1.5 - checkATPForSPOOneDriveTeams
// ---------------------------------------------------------------------------

func TestCheckATPForSPOOneDriveTeams_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ATPConfig: &databag.ATPConfig{
			EnableATPForSPOTeamsODB: true,
		},
	}

	result, err := checkATPForSPOOneDriveTeams(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckATPForSPOOneDriveTeams_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ATPConfig: &databag.ATPConfig{
			EnableATPForSPOTeamsODB: false,
		},
	}

	result, err := checkATPForSPOOneDriveTeams(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when ATP is disabled")
	}
}

func TestCheckATPForSPOOneDriveTeams_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkATPForSPOOneDriveTeams(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil ATP config")
	}
}

// ---------------------------------------------------------------------------
// 2.1.7 - checkAntiPhishingPolicy
// ---------------------------------------------------------------------------

func TestCheckAntiPhishingPolicy_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AntiPhishingPolicy: []databag.AntiPhishingPolicy{
			{
				Name:                                "Default Anti-Phishing",
				IsEnabled:                           true,
				EnableMailboxIntelligence:            true,
				EnableMailboxIntelligenceProtection:  true,
				EnableSpoofIntelligence:              true,
				EnableTargetedUserProtection:         true,
				EnableTargetedDomainProtection:       false,
				EnableOrganizationDomainsProtection:  false,
			},
		},
	}

	result, err := checkAntiPhishingPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckAntiPhishingPolicy_Fail_MissingIntelligence(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AntiPhishingPolicy: []databag.AntiPhishingPolicy{
			{
				Name:                                "Weak Anti-Phishing",
				IsEnabled:                           true,
				EnableMailboxIntelligence:            false,
				EnableMailboxIntelligenceProtection:  true,
				EnableSpoofIntelligence:              true,
				EnableTargetedUserProtection:         true,
			},
		},
	}

	result, err := checkAntiPhishingPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when mailbox intelligence is disabled")
	}
}

func TestCheckAntiPhishingPolicy_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkAntiPhishingPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ---------------------------------------------------------------------------
// 2.1.9 - checkDKIMEnabled
// ---------------------------------------------------------------------------

func TestCheckDKIMEnabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DKIMConfigs: []databag.DKIMConfig{
			{Domain: "test.com", Enabled: true},
			{Domain: "mail.test.com", Enabled: true},
		},
	}

	result, err := checkDKIMEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckDKIMEnabled_Fail_SomeDisabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DKIMConfigs: []databag.DKIMConfig{
			{Domain: "test.com", Enabled: true},
			{Domain: "other.com", Enabled: false},
		},
	}

	result, err := checkDKIMEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when some domains lack DKIM")
	}
}

func TestCheckDKIMEnabled_Fail_NoConfigs(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkDKIMEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no DKIM configs")
	}
}

// ---------------------------------------------------------------------------
// 2.1.11 - checkComprehensiveAttachmentFilter
// ---------------------------------------------------------------------------

func TestCheckComprehensiveAttachmentFilter_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MalwareFilterPolicy: []databag.MalwareFilterPolicy{
			{
				Name:             "Comprehensive Filter",
				IsEnabled:        true,
				EnableFileFilter: true,
				FileTypes: []string{
					"ace", "ani", "app", "cab", "docm", "exe", "iso", "jar", "jnlp",
					"reg", "scr", "vbe", "vbs", "wsc", "wsf", "wsh", "pif", "msi",
				},
			},
		},
	}

	result, err := checkComprehensiveAttachmentFilter(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckComprehensiveAttachmentFilter_Fail_MissingTypes(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MalwareFilterPolicy: []databag.MalwareFilterPolicy{
			{
				Name:             "Partial Filter",
				IsEnabled:        true,
				EnableFileFilter: true,
				FileTypes:        []string{"exe", "scr"},
			},
		},
	}

	result, err := checkComprehensiveAttachmentFilter(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with missing file types")
	}
}

func TestCheckComprehensiveAttachmentFilter_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkComprehensiveAttachmentFilter(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ---------------------------------------------------------------------------
// 2.1.12 - checkConnectionFilterIPAllowList
// ---------------------------------------------------------------------------

func TestCheckConnectionFilterIPAllowList_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConnectionFilter: &databag.ConnectionFilterPolicy{
			IPAllowList: []string{},
		},
	}

	result, err := checkConnectionFilterIPAllowList(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckConnectionFilterIPAllowList_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConnectionFilter: &databag.ConnectionFilterPolicy{
			IPAllowList: []string{"10.0.0.1", "192.168.1.0/24"},
		},
	}

	result, err := checkConnectionFilterIPAllowList(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when IP allow list is not empty")
	}
}

func TestCheckConnectionFilterIPAllowList_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkConnectionFilterIPAllowList(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil connection filter")
	}
}

// ---------------------------------------------------------------------------
// 2.1.13 - checkConnectionFilterSafeList
// ---------------------------------------------------------------------------

func TestCheckConnectionFilterSafeList_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConnectionFilter: &databag.ConnectionFilterPolicy{
			EnableSafeList: false,
		},
	}

	result, err := checkConnectionFilterSafeList(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckConnectionFilterSafeList_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConnectionFilter: &databag.ConnectionFilterPolicy{
			EnableSafeList: true,
		},
	}

	result, err := checkConnectionFilterSafeList(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when safe list is enabled")
	}
}

func TestCheckConnectionFilterSafeList_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkConnectionFilterSafeList(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil connection filter")
	}
}

// ---------------------------------------------------------------------------
// 2.1.14 - checkAntispamAllowedDomains
// ---------------------------------------------------------------------------

func TestCheckAntispamAllowedDomains_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AntispamPolicies: []databag.AntispamPolicy{
			{
				Name:                 "Default Anti-Spam",
				AllowedSenderDomains: []string{},
			},
		},
	}

	result, err := checkAntispamAllowedDomains(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckAntispamAllowedDomains_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AntispamPolicies: []databag.AntispamPolicy{
			{
				Name:                 "Default Anti-Spam",
				AllowedSenderDomains: []string{"trusted.com"},
			},
		},
	}

	result, err := checkAntispamAllowedDomains(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with allowed sender domains")
	}
}

func TestCheckAntispamAllowedDomains_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkAntispamAllowedDomains(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ---------------------------------------------------------------------------
// 2.1.15 - checkOutboundSpamPolicy
// ---------------------------------------------------------------------------

func TestCheckOutboundSpamPolicy_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OutboundSpamPolicies: []databag.OutboundSpamPolicy{
			{
				Name:                                      "Default Outbound",
				IsEnabled:                                 true,
				BccSuspiciousOutboundMail:                 true,
				BccSuspiciousOutboundAdditionalRecipients: []string{"security@test.com"},
				AutoForwardingMode:                        "Off",
			},
		},
	}

	result, err := checkOutboundSpamPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckOutboundSpamPolicy_Fail_AutoForwarding(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OutboundSpamPolicies: []databag.OutboundSpamPolicy{
			{
				Name:                                      "Default Outbound",
				IsEnabled:                                 true,
				BccSuspiciousOutboundMail:                 true,
				BccSuspiciousOutboundAdditionalRecipients: []string{"security@test.com"},
				AutoForwardingMode:                        "Automatic",
			},
		},
	}

	result, err := checkOutboundSpamPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when auto-forwarding is not Off")
	}
}

func TestCheckOutboundSpamPolicy_Fail_NoPolicies(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkOutboundSpamPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with no policies")
	}
}

// ---------------------------------------------------------------------------
// 2.4.4 - checkZAPForTeams
// ---------------------------------------------------------------------------

func TestCheckZAPForTeams_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ZAPConfig: &databag.ZAPConfig{
			ZapEnabled:      true,
			TeamsZapEnabled: true,
		},
	}

	result, err := checkZAPForTeams(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckZAPForTeams_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ZAPConfig: &databag.ZAPConfig{
			ZapEnabled:      true,
			TeamsZapEnabled: false,
		},
	}

	result, err := checkZAPForTeams(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when Teams ZAP is disabled")
	}
}

func TestCheckZAPForTeams_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkZAPForTeams(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil ZAP config")
	}
}

// ---------------------------------------------------------------------------
// DEFENDER_8.6.1 - checkChatReportPolicy
// ---------------------------------------------------------------------------

func TestCheckChatReportPolicy_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ChatReportPolicy: &databag.ChatReportPolicy{
			Name:                 "Default Chat Report",
			IsEnabled:            true,
			ReportToSecurityTeam: true,
		},
	}

	result, err := checkChatReportPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckChatReportPolicy_Fail_NotReporting(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ChatReportPolicy: &databag.ChatReportPolicy{
			Name:                 "Chat Report",
			IsEnabled:            true,
			ReportToSecurityTeam: false,
		},
	}

	result, err := checkChatReportPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when report to security team is disabled")
	}
}

func TestCheckChatReportPolicy_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkChatReportPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil chat report policy")
	}
}

// ---------------------------------------------------------------------------
// DEFENDER_IDENTITY_HEALTH - checkDefenderIdentityHealth
// ---------------------------------------------------------------------------

func TestCheckDefenderIdentityHealth_Pass_NoIssues(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkDefenderIdentityHealth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with no issues, got: %s", result.Message)
	}
}

func TestCheckDefenderIdentityHealth_Pass_AllClosed(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DefenderIdentityHealthIssues: []databag.DefenderIdentityHealthIssue{
			{ID: "1", Title: "Resolved Issue", Severity: "High", Status: "Closed"},
		},
	}

	result, err := checkDefenderIdentityHealth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with all closed issues, got: %s", result.Message)
	}
}

func TestCheckDefenderIdentityHealth_Fail_OpenIssues(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DefenderIdentityHealthIssues: []databag.DefenderIdentityHealthIssue{
			{ID: "1", Title: "Open Issue", Severity: "High", Status: "Open"},
		},
	}

	result, err := checkDefenderIdentityHealth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with open health issues")
	}
}

// ---------------------------------------------------------------------------
// DEFENDER_EXPOSED_CREDS - checkExposedCredentials
// ---------------------------------------------------------------------------

func TestCheckExposedCredentials_Pass(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkExposedCredentials(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckExposedCredentials_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExposedCredentials: []databag.ExposedCredential{
			{
				UserPrincipalName: "admin@test.com",
				ExposureType:      "ClearTextPassword",
				Source:            "DarkWeb",
			},
		},
	}

	result, err := checkExposedCredentials(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with exposed credentials")
	}
}

// ===========================================================================
// Edge case and negative tests
// ===========================================================================

// ---------------------------------------------------------------------------
// 2.1.1 - checkSafeLinksPolicy (edge cases)
// ---------------------------------------------------------------------------

func TestCheckSafeLinksPolicy_MultiplePoliciesOnlyOneCompliant(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeLinksPolicy: []databag.SafeLinksPolicy{
			{
				Name:                    "Non-Compliant",
				IsEnabled:               true,
				ScanUrls:                false,
				DoNotAllowClickThrough:  false,
				EnableForInternalSenders: false,
			},
			{
				Name:                    "Compliant",
				IsEnabled:               true,
				ScanUrls:                true,
				DoNotAllowClickThrough:  true,
				EnableForInternalSenders: true,
			},
		},
	}

	result, err := checkSafeLinksPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when at least one policy is compliant, got: %s", result.Message)
	}
}

func TestCheckSafeLinksPolicy_EmptyPolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:        "test-tenant",
		SafeLinksPolicy: []databag.SafeLinksPolicy{},
	}

	result, err := checkSafeLinksPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty SafeLinksPolicy slice")
	}
}

func TestCheckSafeLinksPolicy_PartialConfig(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeLinksPolicy: []databag.SafeLinksPolicy{
			{
				Name:                    "Partial",
				IsEnabled:               true,
				ScanUrls:                false,
				DoNotAllowClickThrough:  true,
				EnableForInternalSenders: true,
			},
		},
	}

	result, err := checkSafeLinksPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when ScanUrls is false")
	}
}

// ---------------------------------------------------------------------------
// 2.1.2 - checkCommonAttachmentFilter (edge cases)
// ---------------------------------------------------------------------------

func TestCheckCommonAttachmentFilter_MultiplePolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MalwareFilterPolicy: []databag.MalwareFilterPolicy{
			{
				Name:             "Disabled Policy",
				IsEnabled:        false,
				EnableFileFilter: true,
			},
			{
				Name:             "Enabled Policy",
				IsEnabled:        true,
				EnableFileFilter: true,
			},
		},
	}

	result, err := checkCommonAttachmentFilter(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with second policy enabled, got: %s", result.Message)
	}
}

func TestCheckCommonAttachmentFilter_EmptyPolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:            "test-tenant",
		MalwareFilterPolicy: []databag.MalwareFilterPolicy{},
	}

	result, err := checkCommonAttachmentFilter(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty MalwareFilterPolicy slice")
	}
}

// ---------------------------------------------------------------------------
// 2.1.4 - checkSafeAttachmentsPolicy (edge cases)
// ---------------------------------------------------------------------------

func TestCheckSafeAttachments_ReplaceAction(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeAttachmentPolicy: []databag.SafeAttachmentPolicy{
			{
				Name:      "Replace Policy",
				IsEnabled: true,
				Action:    "Replace",
			},
		},
	}

	result, err := checkSafeAttachmentsPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with Replace action, got: %s", result.Message)
	}
}

func TestCheckSafeAttachments_CaseSensitivity(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeAttachmentPolicy: []databag.SafeAttachmentPolicy{
			{
				Name:      "Lowercase Block",
				IsEnabled: true,
				Action:    "block",
			},
		},
	}

	result, err := checkSafeAttachmentsPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with lowercase 'block' action (case-insensitive), got: %s", result.Message)
	}
}

func TestCheckSafeAttachments_MultiplePolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		SafeAttachmentPolicy: []databag.SafeAttachmentPolicy{
			{
				Name:      "Allow Policy",
				IsEnabled: true,
				Action:    "Allow",
			},
			{
				Name:      "Block Policy",
				IsEnabled: true,
				Action:    "Block",
			},
		},
	}

	result, err := checkSafeAttachmentsPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The check iterates all policies; Allow is skipped (non-protective), Block matches and passes
	if !result.Passed {
		t.Fatalf("expected check to pass because the second policy (Block) is a protective action, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// 2.1.5 - checkATPForSPOOneDriveTeams (edge cases)
// ---------------------------------------------------------------------------

func TestCheckATPForSPO_PartialConfig(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ATPConfig: &databag.ATPConfig{
			EnableATPForSPOTeamsODB: true,
			EnableSafeDocs:          false,
		},
	}

	result, err := checkATPForSPOOneDriveTeams(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The check only looks at EnableATPForSPOTeamsODB, so it should pass
	if !result.Passed {
		t.Fatalf("expected check to pass when EnableATPForSPOTeamsODB is true regardless of EnableSafeDocs, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// 2.1.7 - checkAntiPhishingPolicy (edge cases)
// ---------------------------------------------------------------------------

func TestCheckAntiPhishing_MultiplePolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AntiPhishingPolicy: []databag.AntiPhishingPolicy{
			{
				Name:                                "Non-Compliant",
				IsEnabled:                           true,
				EnableMailboxIntelligence:            false,
				EnableMailboxIntelligenceProtection:  false,
				EnableSpoofIntelligence:              false,
				EnableTargetedUserProtection:         false,
			},
			{
				Name:                                "Compliant",
				IsEnabled:                           true,
				EnableMailboxIntelligence:            true,
				EnableMailboxIntelligenceProtection:  true,
				EnableSpoofIntelligence:              true,
				EnableTargetedUserProtection:         true,
			},
		},
	}

	result, err := checkAntiPhishingPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass when at least one policy is compliant, got: %s", result.Message)
	}
}

func TestCheckAntiPhishing_EmptyPolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:           "test-tenant",
		AntiPhishingPolicy: []databag.AntiPhishingPolicy{},
	}

	result, err := checkAntiPhishingPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty AntiPhishingPolicy slice")
	}
}

func TestCheckAntiPhishing_MissingOneProtection(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AntiPhishingPolicy: []databag.AntiPhishingPolicy{
			{
				Name:                                "Almost Compliant",
				IsEnabled:                           true,
				EnableMailboxIntelligence:            true,
				EnableMailboxIntelligenceProtection:  true,
				EnableSpoofIntelligence:              false, // missing this one
				EnableTargetedUserProtection:         true,
			},
		},
	}

	result, err := checkAntiPhishingPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when EnableSpoofIntelligence is false")
	}
}

// ---------------------------------------------------------------------------
// 2.1.9 - checkDKIMEnabled (edge cases)
// ---------------------------------------------------------------------------

func TestCheckDKIM_SingleDomainEnabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DKIMConfigs: []databag.DKIMConfig{
			{Domain: "example.com", Enabled: true},
		},
	}

	result, err := checkDKIMEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with single enabled domain, got: %s", result.Message)
	}
}

func TestCheckDKIM_EmptyDomainList(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:    "test-tenant",
		DKIMConfigs: []databag.DKIMConfig{},
	}

	result, err := checkDKIMEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty DKIMConfigs slice")
	}
}

func TestCheckDKIM_SingleDomainDisabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DKIMConfigs: []databag.DKIMConfig{
			{Domain: "example.com", Enabled: false},
		},
	}

	result, err := checkDKIMEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with single disabled domain")
	}
}

// ---------------------------------------------------------------------------
// 2.1.11 - checkComprehensiveAttachmentFilter (edge cases)
// ---------------------------------------------------------------------------

func TestCheckComprehensiveAttachmentFilter_DuplicateTypes(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MalwareFilterPolicy: []databag.MalwareFilterPolicy{
			{
				Name:             "Duplicate Types Filter",
				IsEnabled:        true,
				EnableFileFilter: true,
				FileTypes: []string{
					"ace", "ace", "ani", "app", "cab", "docm", "exe", "iso", "jar", "jnlp",
					"reg", "scr", "vbe", "vbs", "wsc", "wsf", "wsh", "pif", "msi",
				},
			},
		},
	}

	result, err := checkComprehensiveAttachmentFilter(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass even with duplicate file types, got: %s", result.Message)
	}
}

func TestCheckComprehensiveAttachmentFilter_EmptyFileTypes(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		MalwareFilterPolicy: []databag.MalwareFilterPolicy{
			{
				Name:             "Empty Types Filter",
				IsEnabled:        true,
				EnableFileFilter: true,
				FileTypes:        []string{},
			},
		},
	}

	result, err := checkComprehensiveAttachmentFilter(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when EnableFileFilter is true but FileTypes is empty")
	}
}

// ---------------------------------------------------------------------------
// 2.1.12 - checkConnectionFilterIPAllowList (edge cases)
// ---------------------------------------------------------------------------

func TestCheckConnectionFilterIPAllowList_SingleIP(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ConnectionFilter: &databag.ConnectionFilterPolicy{
			IPAllowList: []string{"10.0.0.1"},
		},
	}

	result, err := checkConnectionFilterIPAllowList(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when IP allow list has a single entry")
	}
}

func TestCheckConnectionFilterIPAllowList_EmptyStruct(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:         "test-tenant",
		ConnectionFilter: &databag.ConnectionFilterPolicy{},
	}

	result, err := checkConnectionFilterIPAllowList(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with default (empty) ConnectionFilterPolicy, got: %s", result.Message)
	}
}

// ---------------------------------------------------------------------------
// 2.1.14 - checkAntispamAllowedDomains (edge cases)
// ---------------------------------------------------------------------------

func TestCheckAntispamAllowedDomains_MultiplePolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AntispamPolicies: []databag.AntispamPolicy{
			{
				Name:                 "Clean Policy",
				AllowedSenderDomains: []string{},
			},
			{
				Name:                 "Dirty Policy",
				AllowedSenderDomains: []string{"spam.com"},
			},
		},
	}

	result, err := checkAntispamAllowedDomains(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when any policy has allowed sender domains")
	}
}

func TestCheckAntispamAllowedDomains_EmptyDomainInList(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		AntispamPolicies: []databag.AntispamPolicy{
			{
				Name:                 "Policy With Empty Domain",
				AllowedSenderDomains: []string{""},
			},
		},
	}

	result, err := checkAntispamAllowedDomains(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// An empty string is still an entry in the slice, so len > 0
	if result.Passed {
		t.Fatal("expected check to fail when allowed sender domains list contains an empty string")
	}
}

// ---------------------------------------------------------------------------
// 2.1.15 - checkOutboundSpamPolicy (edge cases)
// ---------------------------------------------------------------------------

func TestCheckOutboundSpam_AutoForwardCaseSensitivity(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OutboundSpamPolicies: []databag.OutboundSpamPolicy{
			{
				Name:                                      "Lowercase Off",
				IsEnabled:                                 true,
				BccSuspiciousOutboundMail:                 true,
				BccSuspiciousOutboundAdditionalRecipients: []string{"security@test.com"},
				AutoForwardingMode:                        "off",
			},
		},
	}

	result, err := checkOutboundSpamPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The check uses strings.EqualFold, so "off" should match "Off"
	if !result.Passed {
		t.Fatalf("expected check to pass with lowercase 'off' (case-insensitive comparison), got: %s", result.Message)
	}
}

func TestCheckOutboundSpam_MultiplePolicies(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OutboundSpamPolicies: []databag.OutboundSpamPolicy{
			{
				Name:                                      "Non-Compliant",
				IsEnabled:                                 true,
				BccSuspiciousOutboundMail:                 false,
				BccSuspiciousOutboundAdditionalRecipients: []string{},
				AutoForwardingMode:                        "Automatic",
			},
			{
				Name:                                      "Compliant",
				IsEnabled:                                 true,
				BccSuspiciousOutboundMail:                 true,
				BccSuspiciousOutboundAdditionalRecipients: []string{"admin@test.com"},
				AutoForwardingMode:                        "Off",
			},
		},
	}

	result, err := checkOutboundSpamPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The check iterates ALL enabled policies and accumulates issues for each
	if result.Passed {
		t.Fatal("expected check to fail because the first policy has issues")
	}
}

func TestCheckOutboundSpam_NoNotificationRecipients(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		OutboundSpamPolicies: []databag.OutboundSpamPolicy{
			{
				Name:                                      "No Recipients",
				IsEnabled:                                 true,
				BccSuspiciousOutboundMail:                 true,
				BccSuspiciousOutboundAdditionalRecipients: []string{},
				NotifyOutboundSpam:                        true,
				NotifyOutboundSpamRecipients:              []string{},
				AutoForwardingMode:                        "Off",
			},
		},
	}

	result, err := checkOutboundSpamPolicy(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both notification flags are true but both recipient lists are empty
	if result.Passed {
		t.Fatal("expected check to fail when notification is enabled but recipient lists are empty")
	}
}

// ---------------------------------------------------------------------------
// 2.4.4 - checkZAPForTeams (edge cases)
// ---------------------------------------------------------------------------

func TestCheckZAPTeams_PartialConfig(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ZAPConfig: &databag.ZAPConfig{
			ZapEnabled:      true,
			TeamsZapEnabled: false,
		},
	}

	result, err := checkZAPForTeams(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when ZapEnabled is true but TeamsZapEnabled is false")
	}
}

// ---------------------------------------------------------------------------
// DEFENDER_IDENTITY_HEALTH - checkDefenderIdentityHealth (edge cases)
// ---------------------------------------------------------------------------

func TestCheckDefenderIdentityHealth_MixedStatus(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DefenderIdentityHealthIssues: []databag.DefenderIdentityHealthIssue{
			{ID: "1", Title: "Open Issue", Severity: "High", Status: "Open"},
			{ID: "2", Title: "Closed Issue", Severity: "Medium", Status: "Closed"},
			{ID: "3", Title: "Suppressed Issue", Severity: "Low", Status: "Suppressed"},
		},
	}

	result, err := checkDefenderIdentityHealth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when there is at least one open issue among mixed statuses")
	}
}

func TestCheckDefenderIdentityHealth_MultipleSeverities(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		DefenderIdentityHealthIssues: []databag.DefenderIdentityHealthIssue{
			{ID: "1", Title: "High Severity Open", Severity: "High", Status: "Open"},
			{ID: "2", Title: "Low Severity Open", Severity: "Low", Status: "Open"},
		},
	}

	result, err := checkDefenderIdentityHealth(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with multiple open issues of different severities")
	}
}

// ---------------------------------------------------------------------------
// DEFENDER_EXPOSED_CREDS - checkExposedCredentials (edge cases)
// ---------------------------------------------------------------------------

func TestCheckExposedCredentials_MultipleTypes(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		ExposedCredentials: []databag.ExposedCredential{
			{
				UserPrincipalName: "admin@test.com",
				ExposureType:      "ClearTextPassword",
				Source:            "DarkWeb",
			},
			{
				UserPrincipalName: "user@test.com",
				ExposureType:      "NtlmHash",
				Source:            "Pastebin",
			},
		},
	}

	result, err := checkExposedCredentials(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with multiple exposed credentials of different types")
	}
}

func TestCheckExposedCredentials_EmptyCredentials(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:           "test-tenant",
		ExposedCredentials: []databag.ExposedCredential{},
	}

	result, err := checkExposedCredentials(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with empty ExposedCredentials slice, got: %s", result.Message)
	}
}
