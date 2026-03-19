package analyze

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

func init() {
	// 1.1.3 is already registered in cis_entra_checks.go (checkGlobalAdminCount)
	checks.Register("1.1.4", checkAdminReducedLicenses)
	checks.Register("1.2.1", checkM365GroupsPrivate)
	checks.Register("1.3.1", checkPasswordNeverExpire)
	checks.Register("1.3.3", checkExternalCalendarSharingDisabled)
	checks.Register("1.3.6", checkCustomerLockboxEnabled)
	checks.Register("1.3.2", checkIdleSessionTimeout)
	checks.Register("1.3.4", checkUserOwnedAppsRestricted)
	checks.Register("1.3.5", checkFormsPhishingProtection)
	checks.Register("1.3.7", checkThirdPartyStorageRestrictedM365)
	checks.Register("1.3.9", checkSharedBookingsRestricted)
}

// 1.1.4: Ensure admin accounts have a reduced license footprint
func checkAdminReducedLicenses(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	// Collect all admin user IDs from privileged directory roles
	adminUserIDs := make(map[string]bool)
	for _, role := range bag.DirectoryRoles {
		if _, isAdmin := adminRoleTemplateIDs[role.RoleTemplateID]; isAdmin {
			for _, memberID := range role.Members {
				adminUserIDs[memberID] = true
			}
		}
	}

	if len(adminUserIDs) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "No admin users found to evaluate",
		}, nil
	}

	// Check that admin accounts have minimal licenses (ideally 0 or 1 productivity licenses)
	const maxLicenses = 2
	var overLicensed []string
	for _, user := range bag.Users {
		if !adminUserIDs[user.ID] {
			continue
		}
		if len(user.AssignedLicenses) > maxLicenses {
			overLicensed = append(overLicensed, fmt.Sprintf("%s (%d licenses)", user.UserPrincipalName, len(user.AssignedLicenses)))
		}
	}

	if len(overLicensed) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "All admin accounts have a reduced license footprint",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d admin account(s) have excessive licenses", len(overLicensed)),
		Evidence: map[string]any{
			"over_licensed_admins": overLicensed,
		},
	}, nil
}

// 1.2.1: Ensure M365 groups have Private visibility
func checkM365GroupsPrivate(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	var publicGroups []string
	for _, group := range bag.Groups {
		// M365 (Unified) groups should have Private visibility
		isUnified := false
		for _, gt := range group.GroupTypes {
			if strings.EqualFold(gt, "Unified") {
				isUnified = true
				break
			}
		}
		if !isUnified {
			continue
		}
		if !strings.EqualFold(group.Visibility, "Private") {
			publicGroups = append(publicGroups, group.DisplayName)
		}
	}

	if len(publicGroups) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "All M365 (Unified) groups have Private visibility",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d M365 group(s) do not have Private visibility", len(publicGroups)),
		Evidence: map[string]any{
			"public_groups": publicGroups,
		},
	}, nil
}

// 1.3.1: Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'
func checkPasswordNeverExpire(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.OrganizationSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Organization settings not available",
		}, nil
	}

	if bag.OrganizationSettings.PasswordNeverExpires {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Password policy is set to never expire (as recommended with MFA)",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Password expiration is configured; should be set to never expire when MFA is enforced",
		Evidence: map[string]any{
			"passwordNeverExpires":   bag.OrganizationSettings.PasswordNeverExpires,
			"passwordExpirationDays": bag.OrganizationSettings.PasswordExpirationDays,
		},
	}, nil
}

// 1.3.3: Ensure external calendar sharing is disabled
func checkExternalCalendarSharingDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.OrganizationSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Organization settings not available",
		}, nil
	}

	if !bag.OrganizationSettings.CalendarSharingExternal {
		return &checks.CheckResult{
			Passed:  true,
			Message: "External calendar sharing is disabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "External calendar sharing is enabled",
		Evidence: map[string]any{
			"calendarSharingExternal": bag.OrganizationSettings.CalendarSharingExternal,
		},
	}, nil
}

// 1.3.2: Ensure idle session timeout is set to 3 hours or less for unmanaged devices
func checkIdleSessionTimeout(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.OrganizationSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Organization settings not available",
		}, nil
	}

	if bag.OrganizationSettings.IdleSessionTimeout > 0 && bag.OrganizationSettings.IdleSessionTimeout <= 180 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("Idle session timeout is set to %d minutes (within 3-hour limit)", bag.OrganizationSettings.IdleSessionTimeout),
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Idle session timeout is not configured or exceeds 3 hours",
		Evidence: map[string]any{
			"idleSessionTimeout": bag.OrganizationSettings.IdleSessionTimeout,
		},
	}, nil
}

// 1.3.4: Ensure user-owned apps and services are restricted
func checkUserOwnedAppsRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.OrganizationSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Organization settings not available",
		}, nil
	}

	if !bag.OrganizationSettings.UserOwnedAppsEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "User-owned apps and services are restricted",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "User-owned apps and services are allowed",
		Evidence: map[string]any{
			"userOwnedAppsEnabled": bag.OrganizationSettings.UserOwnedAppsEnabled,
		},
	}, nil
}

// 1.3.5: Ensure internal phishing protection for Forms is enabled
func checkFormsPhishingProtection(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.FormsSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Forms settings not available",
		}, nil
	}

	if bag.FormsSettings.InternalPhishingProtection {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Internal phishing protection for Forms is enabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Internal phishing protection for Forms is not enabled",
		Evidence: map[string]any{
			"internalPhishingProtection": bag.FormsSettings.InternalPhishingProtection,
		},
	}, nil
}

// 1.3.7: Ensure third-party storage services are restricted in M365 on the web
func checkThirdPartyStorageRestrictedM365(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.OrganizationSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Organization settings not available",
		}, nil
	}

	if bag.OrganizationSettings.ThirdPartyStorageRestricted {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Third-party storage services are restricted in M365 on the web",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Third-party storage services are not restricted in M365 on the web",
		Evidence: map[string]any{
			"thirdPartyStorageRestricted": bag.OrganizationSettings.ThirdPartyStorageRestricted,
		},
	}, nil
}

// 1.3.9: Ensure shared bookings pages are restricted to select users
func checkSharedBookingsRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.BookingsSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Bookings settings not available",
		}, nil
	}

	if bag.BookingsSettings.SharedBookingsRestricted {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Shared bookings pages are restricted to select users",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Shared bookings pages are not restricted to select users",
		Evidence: map[string]any{
			"sharedBookingsRestricted": bag.BookingsSettings.SharedBookingsRestricted,
		},
	}, nil
}

// 1.3.6: Ensure Customer Lockbox is enabled
func checkCustomerLockboxEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.OrganizationSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Organization settings not available",
		}, nil
	}

	if bag.OrganizationSettings.CustomerLockboxEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Customer Lockbox is enabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Customer Lockbox is not enabled",
		Evidence: map[string]any{
			"customerLockboxEnabled": bag.OrganizationSettings.CustomerLockboxEnabled,
		},
	}, nil
}
