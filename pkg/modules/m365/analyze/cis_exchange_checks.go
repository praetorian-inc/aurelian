package analyze

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

func init() {
	checks.Register("6.1.1", checkOrgMailboxAuditingEnabled)
	checks.Register("6.1.2", checkUserMailboxAuditingActions)
	checks.Register("6.1.3", checkAuditBypassDisabled)
	checks.Register("6.2.1", checkNoTransportRuleForwardingExternal)
	checks.Register("6.2.2", checkNoDomainWhitelistTransportRules)
	checks.Register("6.2.3", checkExternalEmailTaggingEnabled)
	checks.Register("6.3.1", checkOutlookAddInsDisabled)
	checks.Register("6.5.1", checkModernAuthEnabled)
	checks.Register("6.5.2", checkMailTipsFullyEnabled)
	checks.Register("6.5.3", checkThirdPartyStorageDisabled)
	checks.Register("6.5.4", checkSMTPAuthDisabledGlobally)
	checks.Register("1.2.2", checkSharedMailboxSignInDisabled)
	checks.Register("6.5.5", checkDirectSendRestricted)
}

// 6.1.1: Ensure mailbox auditing for E3 users is enabled at the organization level
func checkOrgMailboxAuditingEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ExchangeConfig == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Exchange organization configuration not available",
		}, nil
	}

	// AuditDisabled == false means auditing is enabled
	if !bag.ExchangeConfig.AuditDisabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Organization-level mailbox auditing is enabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Organization-level mailbox auditing is disabled",
		Evidence: map[string]any{
			"auditDisabled": bag.ExchangeConfig.AuditDisabled,
		},
	}, nil
}

// requiredAuditActions defines the minimum audit actions that should be enabled per role.
var requiredAuditActions = map[string][]string{
	"admin": {
		"ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete",
		"Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf",
		"SoftDelete", "Update", "UpdateCalendarDelegation",
		"UpdateFolderPermissions", "UpdateInboxRules",
	},
	"delegate": {
		"ApplyRecord", "Create", "FolderBind", "HardDelete",
		"Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf",
		"SoftDelete", "Update", "UpdateFolderPermissions",
		"UpdateInboxRules",
	},
	"owner": {
		"ApplyRecord", "Create", "HardDelete", "MailboxLogin",
		"Move", "MoveToDeletedItems", "SoftDelete", "Update",
		"UpdateCalendarDelegation", "UpdateFolderPermissions",
		"UpdateInboxRules",
	},
}

// 6.1.2: Ensure user mailbox auditing includes required actions
func checkUserMailboxAuditingActions(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.MailboxAuditConfig) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No mailbox audit configurations available",
		}, nil
	}

	var nonCompliant []string
	for _, mbox := range bag.MailboxAuditConfig {
		if !mbox.AuditEnabled {
			nonCompliant = append(nonCompliant, mbox.Identity+": auditing disabled")
			continue
		}
		if missing := missingActions(mbox.AuditAdmin, requiredAuditActions["admin"]); len(missing) > 0 {
			nonCompliant = append(nonCompliant, fmt.Sprintf("%s: missing admin actions %v", mbox.Identity, missing))
		}
		if missing := missingActions(mbox.AuditDelegate, requiredAuditActions["delegate"]); len(missing) > 0 {
			nonCompliant = append(nonCompliant, fmt.Sprintf("%s: missing delegate actions %v", mbox.Identity, missing))
		}
		if missing := missingActions(mbox.AuditOwner, requiredAuditActions["owner"]); len(missing) > 0 {
			nonCompliant = append(nonCompliant, fmt.Sprintf("%s: missing owner actions %v", mbox.Identity, missing))
		}
	}

	if len(nonCompliant) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "All sampled mailboxes have required audit actions enabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Some mailboxes are missing required audit actions",
		Evidence: map[string]any{
			"non_compliant": nonCompliant,
		},
	}, nil
}

// 6.1.3: Ensure mailbox audit bypass is not enabled for any mailbox
func checkAuditBypassDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.MailboxAuditConfig) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No mailbox audit configurations available",
		}, nil
	}

	var bypassed []string
	for _, mbox := range bag.MailboxAuditConfig {
		if mbox.AuditBypassEnabled {
			bypassed = append(bypassed, mbox.Identity)
		}
	}

	if len(bypassed) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "No mailboxes have audit bypass enabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d mailbox(es) have audit bypass enabled", len(bypassed)),
		Evidence: map[string]any{
			"bypassed_mailboxes": bypassed,
		},
	}, nil
}

// 6.2.1: Ensure mail transport rules do not forward email to external domains
func checkNoTransportRuleForwardingExternal(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	var forwardingRules []string
	for _, rule := range bag.TransportRules {
		if !strings.EqualFold(rule.State, "Enabled") {
			continue
		}
		if len(rule.RedirectMessageTo) > 0 || rule.RouteMessageOutboundConnector != "" {
			forwardingRules = append(forwardingRules, rule.Name)
		}
	}

	if len(forwardingRules) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "No enabled transport rules forward email to external domains",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d transport rule(s) forward email externally", len(forwardingRules)),
		Evidence: map[string]any{
			"forwarding_rules": forwardingRules,
		},
	}, nil
}

// 6.2.2: Ensure mail transport rules do not whitelist specific domains
func checkNoDomainWhitelistTransportRules(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	var whitelistRules []string
	for _, rule := range bag.TransportRules {
		if !strings.EqualFold(rule.State, "Enabled") {
			continue
		}
		if rule.SenderDomainIsWhitelisted || (rule.SetSCL != nil && *rule.SetSCL == -1) {
			whitelistRules = append(whitelistRules, rule.Name)
		}
	}

	if len(whitelistRules) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "No enabled transport rules whitelist specific domains",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d transport rule(s) whitelist specific domains", len(whitelistRules)),
		Evidence: map[string]any{
			"whitelist_rules": whitelistRules,
		},
	}, nil
}

// 6.2.3: Ensure external email tagging is enabled
func checkExternalEmailTaggingEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ExternalEmailTagging == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "External email tagging configuration not available",
		}, nil
	}

	if bag.ExternalEmailTagging.Enabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "External email tagging is enabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "External email tagging is not enabled",
		Evidence: map[string]any{
			"enabled": bag.ExternalEmailTagging.Enabled,
		},
	}, nil
}

// 6.3.1: Ensure Outlook add-ins are not allowed in role assignment policies
func checkOutlookAddInsDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.RoleAssignmentPolicies) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No role assignment policies available",
		}, nil
	}

	addInRoles := []string{
		"My Custom Apps",
		"My Marketplace Apps",
		"My ReadWriteMailbox Apps",
	}

	var nonCompliant []string
	for _, policy := range bag.RoleAssignmentPolicies {
		for _, role := range policy.AssignedRoles {
			for _, addInRole := range addInRoles {
				if strings.EqualFold(role, addInRole) {
					nonCompliant = append(nonCompliant, fmt.Sprintf("%s has role '%s'", policy.Name, role))
				}
			}
		}
	}

	if len(nonCompliant) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "No role assignment policies allow Outlook add-ins",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Role assignment policies allow Outlook add-ins",
		Evidence: map[string]any{
			"non_compliant": nonCompliant,
		},
	}, nil
}

// 6.5.1: Ensure modern authentication for Exchange Online is enabled
func checkModernAuthEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ExchangeConfig == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Exchange organization configuration not available",
		}, nil
	}

	if bag.ExchangeConfig.ModernAuthEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Modern authentication is enabled for Exchange Online",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Modern authentication is not enabled for Exchange Online",
		Evidence: map[string]any{
			"modernAuthEnabled": bag.ExchangeConfig.ModernAuthEnabled,
		},
	}, nil
}

// 6.5.2: Ensure MailTips are enabled for end users
func checkMailTipsFullyEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ExchangeConfig == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Exchange organization configuration not available",
		}, nil
	}

	cfg := bag.ExchangeConfig
	allEnabled := cfg.MailTipsAllTipsEnabled &&
		cfg.MailTipsExternalRecipientsTipsEnabled &&
		cfg.MailTipsGroupMetricsEnabled &&
		cfg.MailTipsLargeAudienceThreshold > 0

	if allEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "All MailTips settings are properly enabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "One or more MailTips settings are not properly configured",
		Evidence: map[string]any{
			"mailTipsAllTipsEnabled":                cfg.MailTipsAllTipsEnabled,
			"mailTipsExternalRecipientsTipsEnabled": cfg.MailTipsExternalRecipientsTipsEnabled,
			"mailTipsGroupMetricsEnabled":           cfg.MailTipsGroupMetricsEnabled,
			"mailTipsLargeAudienceThreshold":        cfg.MailTipsLargeAudienceThreshold,
		},
	}, nil
}

// 6.5.3: Ensure additional storage providers are restricted in Outlook on the web
func checkThirdPartyStorageDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.MailboxPolicies) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No OWA mailbox policies available",
		}, nil
	}

	var nonCompliant []string
	for _, policy := range bag.MailboxPolicies {
		if policy.ThirdPartyFileProvidersEnabled || policy.AdditionalStorageProvidersAvailable {
			nonCompliant = append(nonCompliant, policy.Name)
		}
	}

	if len(nonCompliant) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Third-party storage providers are disabled in all OWA mailbox policies",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d OWA mailbox policy(ies) allow third-party storage providers", len(nonCompliant)),
		Evidence: map[string]any{
			"non_compliant_policies": nonCompliant,
		},
	}, nil
}

// 6.5.4: Ensure SMTP AUTH is disabled globally
func checkSMTPAuthDisabledGlobally(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ExchangeConfig == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Exchange organization configuration not available",
		}, nil
	}

	if bag.ExchangeConfig.SmtpClientAuthenticationDisabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "SMTP AUTH is disabled globally",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "SMTP AUTH is not disabled globally",
		Evidence: map[string]any{
			"smtpClientAuthenticationDisabled": bag.ExchangeConfig.SmtpClientAuthenticationDisabled,
		},
	}, nil
}

// 1.2.2: Ensure sign-in to shared mailboxes is blocked
func checkSharedMailboxSignInDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.SharedMailboxes) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "No shared mailboxes found or data not available",
		}, nil
	}

	var signInEnabled []string
	for _, mbox := range bag.SharedMailboxes {
		if mbox.SignInEnabled || mbox.AccountEnabled {
			signInEnabled = append(signInEnabled, mbox.Identity)
		}
	}

	if len(signInEnabled) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "All shared mailboxes have sign-in blocked",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d shared mailbox(es) have sign-in enabled", len(signInEnabled)),
		Evidence: map[string]any{
			"sign_in_enabled_mailboxes": signInEnabled,
		},
	}, nil
}

// 6.5.5: Ensure direct send submissions are rejected
func checkDirectSendRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ExchangeConfig == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Exchange organization configuration not available",
		}, nil
	}

	if bag.ExchangeConfig.DirectSendRestricted {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Direct send submissions are restricted",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Direct send submissions are not restricted",
		Evidence: map[string]any{
			"directSendRestricted": bag.ExchangeConfig.DirectSendRestricted,
		},
	}, nil
}

// --- Exchange check helpers ---

// missingActions returns required actions that are not present in the actual list.
func missingActions(actual, required []string) []string {
	set := make(map[string]bool, len(actual))
	for _, a := range actual {
		set[strings.ToLower(a)] = true
	}
	var missing []string
	for _, r := range required {
		if !set[strings.ToLower(r)] {
			missing = append(missing, r)
		}
	}
	return missing
}
