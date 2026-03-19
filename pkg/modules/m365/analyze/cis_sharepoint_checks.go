package analyze

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

func init() {
	checks.Register("7.2.1", checkSharePointModernAuth)
	checks.Register("7.2.2", checkSharePointGuestsCannotReshare)
	checks.Register("7.2.3", checkSharePointDomainRestrictions)
	checks.Register("7.2.6", checkSharePointNoAnonymousLinks)
	checks.Register("7.3.2", checkOneDriveSyncBlockedUnmanaged)
	checks.Register("7.2.4", checkOneDriveSharingRestricted)
	checks.Register("7.2.5", checkGuestsCannotReshareItems)
	checks.Register("7.2.7", checkLinkSharingRestricted)
	checks.Register("7.2.9", checkGuestAccessExpires)
	checks.Register("7.2.10", checkReauthVerificationCode)
	checks.Register("7.2.11", checkDefaultLinkPermissionView)
	checks.Register("7.3.1", checkInfectedFileDownloadBlocked)
}

// 7.2.1: Ensure modern authentication for SharePoint applications is required
func checkSharePointModernAuth(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	if !bag.SharePointTenant.LegacyAuthProtocolsEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Legacy authentication protocols are disabled; modern authentication is required",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Legacy authentication protocols are enabled for SharePoint",
		Evidence: map[string]any{
			"legacyAuthProtocolsEnabled": bag.SharePointTenant.LegacyAuthProtocolsEnabled,
		},
	}, nil
}

// 7.2.2: Ensure that external users cannot reshare content
func checkSharePointGuestsCannotReshare(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	if bag.SharePointTenant.PreventExternalUsersFromResharing {
		return &checks.CheckResult{
			Passed:  true,
			Message: "External users are prevented from resharing content",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "External users can reshare content they receive",
		Evidence: map[string]any{
			"preventExternalUsersFromResharing": bag.SharePointTenant.PreventExternalUsersFromResharing,
		},
	}, nil
}

// 7.2.3: Ensure that a domain allowlist or blocklist for sharing is configured
func checkSharePointDomainRestrictions(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	mode := strings.ToLower(bag.SharePointTenant.SharingDomainRestrictionMode)
	if mode == "allowlist" || mode == "blocklist" {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Domain restriction mode is configured: " + bag.SharePointTenant.SharingDomainRestrictionMode,
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No domain allowlist or blocklist is configured for sharing",
		Evidence: map[string]any{
			"sharingDomainRestrictionMode": bag.SharePointTenant.SharingDomainRestrictionMode,
		},
	}, nil
}

// 7.2.6: Ensure that SharePoint external sharing does not allow anonymous links
func checkSharePointNoAnonymousLinks(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	// SharingCapability: Disabled, ExternalUserSharingOnly, ExternalUserAndGuestSharing, ExistingExternalUserSharingOnly
	// "ExternalUserAndGuestSharing" allows anonymous links and should fail.
	cap := strings.ToLower(bag.SharePointTenant.SharingCapability)
	if cap == "disabled" || cap == "externalusersharingonly" || cap == "existingexternalusersharingonly" {
		return &checks.CheckResult{
			Passed:  true,
			Message: "SharePoint external sharing does not allow anonymous links",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "SharePoint external sharing allows anonymous access links",
		Evidence: map[string]any{
			"sharingCapability": bag.SharePointTenant.SharingCapability,
		},
	}, nil
}

// 7.3.2: Ensure OneDrive sync is restricted for unmanaged devices
func checkOneDriveSyncBlockedUnmanaged(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	if bag.SharePointTenant.IsUnmanagedSyncClientForTenantRestricted {
		return &checks.CheckResult{
			Passed:  true,
			Message: "OneDrive sync is blocked on unmanaged devices",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "OneDrive sync is not restricted for unmanaged devices",
		Evidence: map[string]any{
			"isUnmanagedSyncClientForTenantRestricted": bag.SharePointTenant.IsUnmanagedSyncClientForTenantRestricted,
		},
	}, nil
}

// 7.2.4: Ensure OneDrive content sharing is restricted
func checkOneDriveSharingRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	// OneDriveSharingCapability should not allow anonymous access
	cap := strings.ToLower(bag.SharePointTenant.OneDriveSharingCapability)
	if cap == "disabled" || cap == "externalusersharingonly" || cap == "existingexternalusersharingonly" {
		return &checks.CheckResult{
			Passed:  true,
			Message: "OneDrive content sharing is appropriately restricted",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "OneDrive content sharing allows anonymous or unrestricted external access",
		Evidence: map[string]any{
			"oneDriveSharingCapability": bag.SharePointTenant.OneDriveSharingCapability,
		},
	}, nil
}

// 7.2.5: Ensure guests cannot reshare items they don't own
func checkGuestsCannotReshareItems(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	if bag.SharePointTenant.PreventExternalUsersFromResharing {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Guests cannot reshare items they don't own",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Guests can reshare items they don't own",
		Evidence: map[string]any{
			"preventExternalUsersFromResharing": bag.SharePointTenant.PreventExternalUsersFromResharing,
		},
	}, nil
}

// 7.2.7: Ensure link sharing is restricted to Internal or Direct
func checkLinkSharingRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	linkType := strings.ToLower(bag.SharePointTenant.DefaultSharingLinkType)
	if linkType == "internal" || linkType == "direct" {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Default sharing link type is restricted to " + bag.SharePointTenant.DefaultSharingLinkType,
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Default sharing link type is not restricted to Internal or Direct",
		Evidence: map[string]any{
			"defaultSharingLinkType": bag.SharePointTenant.DefaultSharingLinkType,
		},
	}, nil
}

// 7.2.9: Ensure guest access expires automatically
func checkGuestAccessExpires(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	if bag.SharePointTenant.ExternalUserExpireInDays > 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("Guest access expires automatically after %d days", bag.SharePointTenant.ExternalUserExpireInDays),
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Guest access does not expire automatically",
		Evidence: map[string]any{
			"externalUserExpireInDays": bag.SharePointTenant.ExternalUserExpireInDays,
		},
	}, nil
}

// 7.2.10: Ensure reauthentication with verification code is restricted
func checkReauthVerificationCode(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	if bag.SharePointTenant.EmailAttestationReAuthDays > 0 && bag.SharePointTenant.EmailAttestationReAuthDays <= 30 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("Email attestation reauthentication is set to %d days", bag.SharePointTenant.EmailAttestationReAuthDays),
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Email attestation reauthentication is not configured or exceeds 30 days",
		Evidence: map[string]any{
			"emailAttestationReAuthDays": bag.SharePointTenant.EmailAttestationReAuthDays,
		},
	}, nil
}

// 7.2.11: Ensure default sharing link permission is set to View
func checkDefaultLinkPermissionView(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	if strings.EqualFold(bag.SharePointTenant.DefaultLinkPermission, "View") {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Default sharing link permission is set to View",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Default sharing link permission is not set to View",
		Evidence: map[string]any{
			"defaultLinkPermission": bag.SharePointTenant.DefaultLinkPermission,
		},
	}, nil
}

// 7.3.1: Ensure infected files are disallowed for download
func checkInfectedFileDownloadBlocked(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.SharePointTenant == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "SharePoint tenant configuration not available",
		}, nil
	}

	if bag.SharePointTenant.DisallowInfectedFileDownload {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Infected files are disallowed for download",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Infected files can be downloaded",
		Evidence: map[string]any{
			"disallowInfectedFileDownload": bag.SharePointTenant.DisallowInfectedFileDownload,
		},
	}, nil
}
