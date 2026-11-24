package analyze

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

func init() {
	checks.Register("2.1.1", checkSafeLinksPolicy)
	checks.Register("2.1.2", checkCommonAttachmentFilter)
	checks.Register("2.1.4", checkSafeAttachmentsPolicy)
	checks.Register("2.1.5", checkATPForSPOOneDriveTeams)
	checks.Register("2.1.7", checkAntiPhishingPolicy)
	checks.Register("2.1.9", checkDKIMEnabled)
	checks.Register("2.1.11", checkComprehensiveAttachmentFilter)
	checks.Register("2.1.12", checkConnectionFilterIPAllowList)
	checks.Register("2.1.13", checkConnectionFilterSafeList)
	checks.Register("2.1.14", checkAntispamAllowedDomains)
	checks.Register("2.1.15", checkOutboundSpamPolicy)
	checks.Register("2.4.4", checkZAPForTeams)
	checks.Register("DEFENDER_8.6.1", checkChatReportPolicy)
	checks.Register("DEFENDER_IDENTITY_HEALTH", checkDefenderIdentityHealth)
	checks.Register("DEFENDER_EXPOSED_CREDS", checkExposedCredentials)
	checks.Register("2.1.3", checkMalwareInternalNotifications)
	checks.Register("2.1.6", checkSpamNotifyAdmins)
	checks.Register("2.1.8", checkSPFRecords)
	checks.Register("2.1.10", checkDMARCRecords)
}

// comprehensiveFileTypes is the set of file extensions that CIS recommends blocking
// in the common attachment type filter. Declared as a function to prevent mutation.
func comprehensiveFileTypes() []string {
	return []string{
		"ace", "ani", "app", "cab", "docm", "exe", "iso", "jar", "jnlp",
		"reg", "scr", "vbe", "vbs", "wsc", "wsf", "wsh", "pif", "msi",
	}
}

// 2.1.1: Ensure Safe Links for email messages is enabled and properly configured.
func checkSafeLinksPolicy(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.SafeLinksPolicy) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No Safe Links policies found",
		}, nil
	}

	for _, policy := range bag.SafeLinksPolicy {
		if !policy.IsEnabled {
			continue
		}
		if policy.ScanUrls && policy.DoNotAllowClickThrough && policy.EnableForInternalSenders {
			return &checks.CheckResult{
				Passed:  true,
				Message: "Safe Links policy '" + policy.Name + "' is enabled and properly configured",
				Evidence: map[string]any{
					"policy_name":              policy.Name,
					"scanUrls":                 policy.ScanUrls,
					"doNotAllowClickThrough":   policy.DoNotAllowClickThrough,
					"enableForInternalSenders":  policy.EnableForInternalSenders,
				},
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No Safe Links policy is fully configured (scanUrls, doNotAllowClickThrough, enableForInternalSenders all required)",
		Evidence: map[string]any{
			"policies_checked": len(bag.SafeLinksPolicy),
		},
	}, nil
}

// 2.1.2: Ensure the common attachment types filter is enabled in the malware policy.
func checkCommonAttachmentFilter(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.MalwareFilterPolicy) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No malware filter policies found",
		}, nil
	}

	for _, policy := range bag.MalwareFilterPolicy {
		if !policy.IsEnabled {
			continue
		}
		if policy.EnableFileFilter {
			return &checks.CheckResult{
				Passed:  true,
				Message: "Malware filter policy '" + policy.Name + "' has common attachment types filter enabled",
				Evidence: map[string]any{
					"policy_name":      policy.Name,
					"enableFileFilter": policy.EnableFileFilter,
				},
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No malware filter policy has the common attachment types filter enabled",
		Evidence: map[string]any{
			"policies_checked": len(bag.MalwareFilterPolicy),
		},
	}, nil
}

// 2.1.4: Ensure Safe Attachments policy is enabled.
func checkSafeAttachmentsPolicy(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.SafeAttachmentPolicy) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No Safe Attachments policies found",
		}, nil
	}

	for _, policy := range bag.SafeAttachmentPolicy {
		if !policy.IsEnabled {
			continue
		}
		// Action should be Block, Replace, or DynamicDelivery (not Allow or Off)
		action := strings.ToLower(policy.Action)
		if action == "block" || action == "replace" || action == "dynamicdelivery" {
			return &checks.CheckResult{
				Passed:  true,
				Message: "Safe Attachments policy '" + policy.Name + "' is enabled with action '" + policy.Action + "'",
				Evidence: map[string]any{
					"policy_name": policy.Name,
					"action":      policy.Action,
				},
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No Safe Attachments policy is enabled with a protective action (Block, Replace, or DynamicDelivery)",
		Evidence: map[string]any{
			"policies_checked": len(bag.SafeAttachmentPolicy),
		},
	}, nil
}

// 2.1.5: Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is enabled.
func checkATPForSPOOneDriveTeams(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ATPConfig == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "ATP configuration not available",
		}, nil
	}

	if bag.ATPConfig.EnableATPForSPOTeamsODB {
		return &checks.CheckResult{
			Passed:  true,
			Message: "ATP Safe Attachments is enabled for SharePoint, OneDrive, and Teams",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "ATP Safe Attachments is not enabled for SharePoint, OneDrive, and Teams",
		Evidence: map[string]any{
			"enableATPForSPOTeamsODB": bag.ATPConfig.EnableATPForSPOTeamsODB,
		},
	}, nil
}

// 2.1.7: Ensure anti-phishing policy is configured with impersonation protection.
func checkAntiPhishingPolicy(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.AntiPhishingPolicy) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No anti-phishing policies found",
		}, nil
	}

	for _, policy := range bag.AntiPhishingPolicy {
		if !policy.IsEnabled {
			continue
		}
		if policy.EnableMailboxIntelligence &&
			policy.EnableMailboxIntelligenceProtection &&
			policy.EnableSpoofIntelligence &&
			(policy.EnableTargetedUserProtection || policy.EnableTargetedDomainProtection || policy.EnableOrganizationDomainsProtection) {
			return &checks.CheckResult{
				Passed:  true,
				Message: "Anti-phishing policy '" + policy.Name + "' has impersonation protection configured",
				Evidence: map[string]any{
					"policy_name":                        policy.Name,
					"enableMailboxIntelligence":           policy.EnableMailboxIntelligence,
					"enableMailboxIntelligenceProtection": policy.EnableMailboxIntelligenceProtection,
					"enableSpoofIntelligence":             policy.EnableSpoofIntelligence,
					"enableTargetedUserProtection":        policy.EnableTargetedUserProtection,
					"enableTargetedDomainProtection":      policy.EnableTargetedDomainProtection,
					"enableOrganizationDomainsProtection": policy.EnableOrganizationDomainsProtection,
				},
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No anti-phishing policy has full impersonation protection (mailbox intelligence, spoof intelligence, and at least one targeted protection)",
		Evidence: map[string]any{
			"policies_checked": len(bag.AntiPhishingPolicy),
		},
	}, nil
}

// 2.1.9: Ensure DKIM is enabled for all Exchange Online domains.
func checkDKIMEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.DKIMConfigs) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No DKIM configurations found",
		}, nil
	}

	var disabledDomains []string
	for _, cfg := range bag.DKIMConfigs {
		if !cfg.Enabled {
			disabledDomains = append(disabledDomains, cfg.Domain)
		}
	}

	if len(disabledDomains) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("DKIM is enabled for all %d domain(s)", len(bag.DKIMConfigs)),
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("DKIM is not enabled for %d domain(s)", len(disabledDomains)),
		Evidence: map[string]any{
			"disabled_domains": disabledDomains,
			"total_domains":    len(bag.DKIMConfigs),
		},
	}, nil
}

// 2.1.11: Ensure a comprehensive set of attachment types is filtered in the malware policy.
func checkComprehensiveAttachmentFilter(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.MalwareFilterPolicy) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No malware filter policies found",
		}, nil
	}

	for _, policy := range bag.MalwareFilterPolicy {
		if !policy.IsEnabled || !policy.EnableFileFilter {
			continue
		}

		blocked := make(map[string]bool)
		for _, ft := range policy.FileTypes {
			blocked[strings.ToLower(ft)] = true
		}

		var missing []string
		for _, required := range comprehensiveFileTypes() {
			if !blocked[required] {
				missing = append(missing, required)
			}
		}

		if len(missing) == 0 {
			return &checks.CheckResult{
				Passed:  true,
				Message: "Malware filter policy '" + policy.Name + "' blocks all recommended attachment types",
				Evidence: map[string]any{
					"policy_name":  policy.Name,
					"blocked_types": len(policy.FileTypes),
				},
			}, nil
		}
	}

	// No policy covers all recommended types; find the best one and report what's missing.
	bestPolicy := ""
	var bestMissing []string
	for _, policy := range bag.MalwareFilterPolicy {
		if !policy.IsEnabled || !policy.EnableFileFilter {
			continue
		}
		blocked := make(map[string]bool)
		for _, ft := range policy.FileTypes {
			blocked[strings.ToLower(ft)] = true
		}
		var missing []string
		for _, required := range comprehensiveFileTypes() {
			if !blocked[required] {
				missing = append(missing, required)
			}
		}
		if bestPolicy == "" || len(missing) < len(bestMissing) {
			bestPolicy = policy.Name
			bestMissing = missing
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No malware filter policy blocks all recommended attachment types",
		Evidence: map[string]any{
			"closest_policy": bestPolicy,
			"missing_types":  bestMissing,
		},
	}, nil
}

// 2.1.12: Ensure the connection filter IP allow list is empty.
func checkConnectionFilterIPAllowList(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ConnectionFilter == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Connection filter policy not available",
		}, nil
	}

	if len(bag.ConnectionFilter.IPAllowList) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Connection filter IP allow list is empty",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("Connection filter IP allow list contains %d entries", len(bag.ConnectionFilter.IPAllowList)),
		Evidence: map[string]any{
			"ip_allow_list": bag.ConnectionFilter.IPAllowList,
		},
	}, nil
}

// 2.1.13: Ensure the connection filter safe list is disabled.
func checkConnectionFilterSafeList(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ConnectionFilter == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Connection filter policy not available",
		}, nil
	}

	if !bag.ConnectionFilter.EnableSafeList {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Connection filter safe list is disabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Connection filter safe list is enabled (should be disabled)",
		Evidence: map[string]any{
			"enableSafeList": bag.ConnectionFilter.EnableSafeList,
		},
	}, nil
}

// 2.1.14: Ensure no allowed domains exist in the inbound anti-spam policy.
func checkAntispamAllowedDomains(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.AntispamPolicies) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No anti-spam policies found",
		}, nil
	}

	var violatingPolicies []string
	var allAllowedDomains []string

	for _, policy := range bag.AntispamPolicies {
		if len(policy.AllowedSenderDomains) > 0 {
			violatingPolicies = append(violatingPolicies, policy.Name)
			allAllowedDomains = append(allAllowedDomains, policy.AllowedSenderDomains...)
		}
	}

	if len(violatingPolicies) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "No inbound anti-spam policy has allowed sender domains",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d anti-spam policy(ies) have allowed sender domains configured", len(violatingPolicies)),
		Evidence: map[string]any{
			"violating_policies": violatingPolicies,
			"allowed_domains":    allAllowedDomains,
		},
	}, nil
}

// 2.1.15: Ensure outbound spam policy has notifications configured and auto-forwarding is disabled.
func checkOutboundSpamPolicy(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.OutboundSpamPolicies) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No outbound spam policies found",
		}, nil
	}

	var issues []string

	for _, policy := range bag.OutboundSpamPolicies {
		if !policy.IsEnabled {
			continue
		}

		// Check notification configuration
		hasNotification := (policy.BccSuspiciousOutboundMail && len(policy.BccSuspiciousOutboundAdditionalRecipients) > 0) ||
			(policy.NotifyOutboundSpam && len(policy.NotifyOutboundSpamRecipients) > 0)
		if !hasNotification {
			issues = append(issues, fmt.Sprintf("policy '%s' lacks outbound spam notification recipients", policy.Name))
		}

		// Check auto-forwarding is disabled
		if !strings.EqualFold(policy.AutoForwardingMode, "Off") {
			issues = append(issues, fmt.Sprintf("policy '%s' has auto-forwarding mode set to '%s' (should be Off)", policy.Name, policy.AutoForwardingMode))
		}
	}

	if len(issues) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Outbound spam policies have notifications configured and auto-forwarding is disabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Outbound spam policy configuration issues found",
		Evidence: map[string]any{
			"issues": issues,
		},
	}, nil
}

// 2.4.4: Ensure Zero-hour Auto Purge (ZAP) for Teams is enabled.
func checkZAPForTeams(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ZAPConfig == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "ZAP configuration not available",
		}, nil
	}

	if bag.ZAPConfig.TeamsZapEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Zero-hour Auto Purge (ZAP) for Teams is enabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Zero-hour Auto Purge (ZAP) for Teams is not enabled",
		Evidence: map[string]any{
			"teamsZapEnabled": bag.ZAPConfig.TeamsZapEnabled,
			"zapEnabled":      bag.ZAPConfig.ZapEnabled,
		},
	}, nil
}

// 8.6.1: Ensure the chat report policy is configured for Defender reporting.
func checkChatReportPolicy(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.ChatReportPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Chat report policy not available",
		}, nil
	}

	if bag.ChatReportPolicy.IsEnabled && bag.ChatReportPolicy.ReportToSecurityTeam {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Chat report policy '" + bag.ChatReportPolicy.Name + "' is enabled and reports to security team",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Chat report policy is not fully configured",
		Evidence: map[string]any{
			"isEnabled":            bag.ChatReportPolicy.IsEnabled,
			"reportToSecurityTeam": bag.ChatReportPolicy.ReportToSecurityTeam,
		},
	}, nil
}

// BEYOND CIS: Ensure there are no unresolved Defender for Identity health issues.
func checkDefenderIdentityHealth(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.DefenderIdentityHealthIssues) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "No unresolved Defender for Identity health issues found",
		}, nil
	}

	var openIssues []databag.DefenderIdentityHealthIssue
	for _, issue := range bag.DefenderIdentityHealthIssues {
		if strings.EqualFold(issue.Status, "Open") {
			openIssues = append(openIssues, issue)
		}
	}

	if len(openIssues) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "No open Defender for Identity health issues (all issues are closed or suppressed)",
		}, nil
	}

	issueSummaries := make([]map[string]string, 0, len(openIssues))
	for _, issue := range openIssues {
		issueSummaries = append(issueSummaries, map[string]string{
			"id":       issue.ID,
			"title":    issue.Title,
			"severity": issue.Severity,
		})
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d unresolved Defender for Identity health issue(s) found", len(openIssues)),
		Evidence: map[string]any{
			"open_issues":  issueSummaries,
			"total_issues": len(bag.DefenderIdentityHealthIssues),
		},
	}, nil
}

// BEYOND CIS: Ensure privileged users have no exposed credentials.
func checkExposedCredentials(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.ExposedCredentials) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "No exposed credentials found for privileged users",
		}, nil
	}

	exposedSummaries := make([]map[string]string, 0, len(bag.ExposedCredentials))
	for _, cred := range bag.ExposedCredentials {
		exposedSummaries = append(exposedSummaries, map[string]string{
			"userPrincipalName": cred.UserPrincipalName,
			"exposureType":      cred.ExposureType,
			"source":            cred.Source,
		})
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d privileged user(s) have exposed credentials", len(bag.ExposedCredentials)),
		Evidence: map[string]any{
			"exposed_credentials": exposedSummaries,
		},
	}, nil
}

// 2.1.3: Ensure notifications for internal users sending malware is enabled
func checkMalwareInternalNotifications(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.MalwareFilterPolicy) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No malware filter policies found",
		}, nil
	}

	for _, policy := range bag.MalwareFilterPolicy {
		if !policy.IsEnabled {
			continue
		}
		if policy.EnableInternalSenderAdminNotifications {
			return &checks.CheckResult{
				Passed:  true,
				Message: "Malware filter policy '" + policy.Name + "' has internal sender admin notifications enabled",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No malware filter policy has internal sender admin notifications enabled",
		Evidence: map[string]any{
			"policies_checked": len(bag.MalwareFilterPolicy),
		},
	}, nil
}

// 2.1.6: Ensure spam policies notify administrators
func checkSpamNotifyAdmins(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SpamNotificationPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Spam notification policy not available",
		}, nil
	}

	if bag.SpamNotificationPolicy.NotifyAdmins {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Spam policies are configured to notify administrators",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Spam policies are not configured to notify administrators",
		Evidence: map[string]any{
			"notifyAdmins": bag.SpamNotificationPolicy.NotifyAdmins,
		},
	}, nil
}

// 2.1.8: Ensure SPF records are published for all Exchange domains
func checkSPFRecords(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.DomainSPFRecords) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No domain SPF record data available",
		}, nil
	}

	var missingSPF []string
	for _, record := range bag.DomainSPFRecords {
		if !record.HasSPF {
			missingSPF = append(missingSPF, record.Domain)
		}
	}

	if len(missingSPF) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("SPF records are published for all %d Exchange domain(s)", len(bag.DomainSPFRecords)),
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("SPF records are missing for %d domain(s)", len(missingSPF)),
		Evidence: map[string]any{
			"domains_missing_spf": missingSPF,
			"total_domains":       len(bag.DomainSPFRecords),
		},
	}, nil
}

// 2.1.10: Ensure DMARC records are published for all Exchange domains
func checkDMARCRecords(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.DomainDMARCRecords) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No domain DMARC record data available",
		}, nil
	}

	var missingDMARC []string
	for _, record := range bag.DomainDMARCRecords {
		if !record.HasDMARC {
			missingDMARC = append(missingDMARC, record.Domain)
		}
	}

	if len(missingDMARC) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("DMARC records are published for all %d Exchange domain(s)", len(bag.DomainDMARCRecords)),
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("DMARC records are missing for %d domain(s)", len(missingDMARC)),
		Evidence: map[string]any{
			"domains_missing_dmarc": missingDMARC,
			"total_domains":         len(bag.DomainDMARCRecords),
		},
	}, nil
}
