package analyze

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

// Well-known Entra ID admin role template IDs
var adminRoleTemplateIDs = map[string]string{
	"62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
	"fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
	"29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
	"f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
	"194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
	"729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
	"b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
	"b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
	"e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
	"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
	"158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
	"966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
	"7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
	"c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
	"e6d1a23a-da11-4be4-9570-befc86d067a7": "Compliance Administrator",
}

// globalAdminRoleTemplateID is the well-known template ID for Global Administrator.
const globalAdminRoleTemplateID = "62e90394-69f5-4237-9190-012177145e10"

func init() {
	// --- Existing checks ---
	checks.Register("5.2.2.1", checkMFARequiredAdmins)
	checks.Register("5.2.2.2", checkMFARequiredAllUsers)
	checks.Register("5.3.1", checkBlockLegacyAuth)
	checks.Register("5.1.2.1", checkGuestAccessRestricted)
	checks.Register("5.1.5.1", checkUserConsentDisabled)

	// --- Conditional Access checks ---
	checks.Register("5.2.2.5", checkPhishingResistantMFAAdmins)
	checks.Register("5.2.2.6", checkUserRiskBasedCA)
	checks.Register("5.2.2.7", checkSignInRiskBasedCA)
	checks.Register("5.2.2.9", checkManagedDeviceRequired)
	checks.Register("5.2.2.10", checkManagedDeviceForMFARegistration)
	checks.Register("5.2.2.11", checkAdminSignInFrequency)
	checks.Register("5.2.2.12", checkDeviceCodeFlowBlocked)

	// --- Entra ID settings checks ---
	checks.Register("5.1.2.3", checkDefaultUsersCannotCreateTenants)
	checks.Register("5.1.2.4", checkAdminPortalsRestricted)
	checks.Register("5.1.3.1", checkDynamicGroupForGuests)
	checks.Register("5.1.5.2", checkAdminConsentWorkflowEnabled)
	checks.Register("5.1.6.1", checkThirdPartyAppsNotAllowed)
	checks.Register("5.1.6.2", checkGuestUserAccessRestrictions)
	checks.Register("5.1.6.3", checkGuestInvitesRestricted)
	checks.Register("5.1.8.1", checkPasswordHashSyncEnabled)

	// --- User-level checks ---
	checks.Register("5.2.3.4", checkUsersAreMFACapable)

	// --- Admin identity checks (CIS section 1) ---
	checks.Register("1.1.1", checkAdminUsersCloudOnly)
	checks.Register("1.1.2", checkBreakGlassHasFIDO2)
	checks.Register("1.1.3", checkGlobalAdminCount)

	// --- New CIS v6.0 Entra checks ---
	checks.Register("5.1.2.2", checkThirdPartyIntegratedAppsBlocked)
	checks.Register("5.1.3.2", checkUsersCannotCreateSecurityGroups)
	checks.Register("5.1.4.1", checkDeviceJoinRestricted)
	checks.Register("5.1.4.2", checkMaxDevicesPerUser)
	checks.Register("5.1.4.3", checkGANotLocalAdmin)
	checks.Register("5.1.4.4", checkAdditionalLocalAdminsLimited)
	checks.Register("5.1.4.5", checkLAPSEnabled)
	checks.Register("5.1.4.6", checkBitlockerKeyRecoveryRestricted)
	checks.Register("5.2.3.2", checkCustomBannedPasswords)
	checks.Register("5.2.3.3", checkPasswordProtectionOnPrem)
	checks.Register("5.2.3.5", checkWeakAuthMethodsDisabled)
	checks.Register("5.3.2", checkAccessReviewsForGuests)

	// --- Beyond-CIS / Prowler extra checks ---
	checks.Register("EXTRA.1", checkSMSVoiceAuthDisabled)
	checks.Register("EXTRA.2", checkCACoversAllCloudApps)
}

// ============================================================================
// Existing checks (unchanged)
// ============================================================================

// 5.2.2.1: Ensure multifactor authentication is required for administrative roles
func checkMFARequiredAdmins(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !includesAdminRoles(policy) {
			continue
		}
		if requiresMFA(policy) {
			return &checks.CheckResult{
				Passed:  true,
				Message: "CA policy '" + policy.DisplayName + "' requires MFA for admin roles",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy found requiring MFA for administrative roles",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// 5.2.2.2: Ensure multifactor authentication is required for all users
func checkMFARequiredAllUsers(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !includesAllUsers(policy) {
			continue
		}
		if !includesAllApps(policy) {
			continue
		}
		if requiresMFA(policy) {
			return &checks.CheckResult{
				Passed:  true,
				Message: "CA policy '" + policy.DisplayName + "' requires MFA for all users",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy found requiring MFA for all users",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// 5.3.1: Ensure legacy authentication is blocked
func checkBlockLegacyAuth(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !includesAllUsers(policy) {
			continue
		}
		if !targetsLegacyClients(policy) {
			continue
		}
		if blocksAccess(policy) {
			return &checks.CheckResult{
				Passed:  true,
				Message: "CA policy '" + policy.DisplayName + "' blocks legacy authentication",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy found blocking legacy authentication for all users",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// 5.1.2.1: Ensure guest user access is restricted
func checkGuestAccessRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthorizationPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authorization policy not available",
		}, nil
	}

	// The most restrictive guest role ID is 2af84b1e-32c8-42b7-82bc-daa82404023b
	// "Guest user access is restricted to properties and memberships of their own directory objects"
	restrictedGuestRoleID := "2af84b1e-32c8-42b7-82bc-daa82404023b"

	if bag.AuthorizationPolicy.GuestUserRoleID == restrictedGuestRoleID {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Guest user access is restricted to most restrictive level",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Guest user access is not set to the most restrictive level",
		Evidence: map[string]any{
			"current_guest_role_id": bag.AuthorizationPolicy.GuestUserRoleID,
			"expected_role_id":      restrictedGuestRoleID,
		},
	}, nil
}

// 5.1.5.1: Ensure user consent to apps is not allowed
func checkUserConsentDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthorizationPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authorization policy not available",
		}, nil
	}

	if bag.AuthorizationPolicy.DefaultUserRolePermissions == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Default user role permissions not available",
		}, nil
	}

	// Check if users are not allowed to create apps (proxy for consent)
	if !bag.AuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateApps {
		return &checks.CheckResult{
			Passed:  true,
			Message: "User consent to apps is disabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Users are allowed to consent to apps",
		Evidence: map[string]any{
			"allowedToCreateApps": bag.AuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateApps,
		},
	}, nil
}

// ============================================================================
// New Conditional Access checks
// ============================================================================

// 5.2.2.5: Ensure phishing-resistant MFA strength is required for administrators
func checkPhishingResistantMFAAdmins(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !includesAdminRoles(policy) {
			continue
		}
		if requiresPhishingResistantMFA(policy) {
			return &checks.CheckResult{
				Passed:  true,
				Message: "CA policy '" + policy.DisplayName + "' requires phishing-resistant MFA for admin roles",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy requires phishing-resistant MFA for administrators",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// 5.2.2.6: Ensure user risk-based Conditional Access policy is configured
func checkUserRiskBasedCA(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !includesAllUsers(policy) {
			continue
		}
		if len(policy.UserRiskLevels) > 0 {
			return &checks.CheckResult{
				Passed:  true,
				Message: "CA policy '" + policy.DisplayName + "' enforces user risk-based conditions",
				Evidence: map[string]any{
					"user_risk_levels": policy.UserRiskLevels,
				},
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy found with user risk-based conditions for all users",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// 5.2.2.7: Ensure sign-in risk-based Conditional Access policy is configured
func checkSignInRiskBasedCA(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !includesAllUsers(policy) {
			continue
		}
		if len(policy.SignInRiskLevels) > 0 {
			return &checks.CheckResult{
				Passed:  true,
				Message: "CA policy '" + policy.DisplayName + "' enforces sign-in risk-based conditions",
				Evidence: map[string]any{
					"sign_in_risk_levels": policy.SignInRiskLevels,
				},
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy found with sign-in risk-based conditions for all users",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// 5.2.2.9: Ensure a managed device is required for authentication
func checkManagedDeviceRequired(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !includesAllUsers(policy) {
			continue
		}
		if !includesAllApps(policy) {
			continue
		}
		if requiresCompliantDevice(policy) {
			return &checks.CheckResult{
				Passed:  true,
				Message: "CA policy '" + policy.DisplayName + "' requires a compliant/managed device",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy requires a managed device for all users and all apps",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// 5.2.2.10: Ensure a managed device is required for MFA registration
func checkManagedDeviceForMFARegistration(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !targetsUserActionMFARegistration(policy) {
			continue
		}
		if requiresCompliantDevice(policy) {
			return &checks.CheckResult{
				Passed:  true,
				Message: "CA policy '" + policy.DisplayName + "' requires a managed device for MFA registration",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy requires a managed device for MFA registration",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// 5.2.2.11: Ensure sign-in frequency is enforced for admin sessions
func checkAdminSignInFrequency(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !includesAdminRoles(policy) {
			continue
		}
		if policy.SignInFrequencyEnabled && policy.SignInFrequencyValue != nil {
			return &checks.CheckResult{
				Passed:  true,
				Message: fmt.Sprintf("CA policy '%s' enforces sign-in frequency of %d %s for admin roles", policy.DisplayName, *policy.SignInFrequencyValue, policy.SignInFrequencyUnit),
				Evidence: map[string]any{
					"sign_in_frequency_value": *policy.SignInFrequencyValue,
					"sign_in_frequency_unit":  policy.SignInFrequencyUnit,
				},
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy enforces sign-in frequency for admin roles",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// 5.2.2.12: Ensure device code flow is blocked
func checkDeviceCodeFlowBlocked(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !includesAllUsers(policy) {
			continue
		}
		if targetsDeviceCodeFlow(policy) && blocksAccess(policy) {
			return &checks.CheckResult{
				Passed:  true,
				Message: "CA policy '" + policy.DisplayName + "' blocks device code flow",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy found blocking device code flow for all users",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// ============================================================================
// Entra ID settings checks
// ============================================================================

// 5.1.2.3: Ensure default users cannot create tenants
func checkDefaultUsersCannotCreateTenants(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthorizationPolicy == nil || bag.AuthorizationPolicy.DefaultUserRolePermissions == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authorization policy or default user role permissions not available",
		}, nil
	}

	if !bag.AuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateTenants {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Default users are not allowed to create tenants",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Default users are allowed to create tenants",
		Evidence: map[string]any{
			"allowedToCreateTenants": true,
		},
	}, nil
}

// 5.1.2.4: Ensure admin portals are restricted to admin roles only
func checkAdminPortalsRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AdminPortalSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Admin portal settings not available",
		}, nil
	}

	if bag.AdminPortalSettings.RestrictNonAdminUsers {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Access to admin portals is restricted to admin roles only",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Non-admin users can access admin portals",
		Evidence: map[string]any{
			"restrictNonAdminUsers": false,
		},
	}, nil
}

// 5.1.3.1: Ensure a dynamic group for guest users exists
func checkDynamicGroupForGuests(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, group := range bag.Groups {
		if !isDynamicGroup(group) {
			continue
		}
		// Check if the membership rule targets guest users (user.userType -eq "Guest")
		ruleLower := strings.ToLower(group.MembershipRule)
		if strings.Contains(ruleLower, "user.usertype") && strings.Contains(ruleLower, "guest") {
			return &checks.CheckResult{
				Passed:  true,
				Message: "Dynamic group '" + group.DisplayName + "' targets guest users",
				Evidence: map[string]any{
					"group_id":        group.ID,
					"membership_rule": group.MembershipRule,
				},
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No dynamic group found targeting guest users",
		Evidence: map[string]any{
			"groups_checked": len(bag.Groups),
		},
	}, nil
}

// 5.1.5.2: Ensure admin consent workflow is enabled
func checkAdminConsentWorkflowEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AdminConsentPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Admin consent request policy not available",
		}, nil
	}

	if bag.AdminConsentPolicy.IsEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Admin consent workflow is enabled",
			Evidence: map[string]any{
				"notifyReviewers":  bag.AdminConsentPolicy.NotifyReviewers,
				"remindersEnabled": bag.AdminConsentPolicy.RemindersEnabled,
			},
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Admin consent workflow is not enabled",
		Evidence: map[string]any{
			"isEnabled": false,
		},
	}, nil
}

// 5.1.6.1: Ensure third-party integrated apps are not allowed (users cannot register apps)
func checkThirdPartyAppsNotAllowed(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthorizationPolicy == nil || bag.AuthorizationPolicy.DefaultUserRolePermissions == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authorization policy or default user role permissions not available",
		}, nil
	}

	perms := bag.AuthorizationPolicy.DefaultUserRolePermissions

	// Both app creation and consent should be restricted
	if perms.AllowedToCreateApps {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Users are allowed to register third-party/integrated applications",
			Evidence: map[string]any{
				"allowedToCreateApps": true,
			},
		}, nil
	}

	return &checks.CheckResult{
		Passed:  true,
		Message: "Users cannot register third-party/integrated applications",
	}, nil
}

// 5.1.6.2: Ensure guest user access restrictions are configured
// This complements 5.1.2.1 but also checks that GuestUserRoleID is at least at the
// "limited access" level (10dae51f-b6af-4016-8d66-8c2a99b929b3) or more restrictive.
func checkGuestUserAccessRestrictions(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthorizationPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authorization policy not available",
		}, nil
	}

	// Acceptable guest role IDs (from most restrictive to limited):
	// 2af84b1e-32c8-42b7-82bc-daa82404023b = most restrictive (own objects only)
	// 10dae51f-b6af-4016-8d66-8c2a99b929b3 = limited access
	// a0b1b346-4d3e-4e8b-98f8-753987be4970 = same as member users (least restrictive, FAIL)
	restrictedIDs := map[string]bool{
		"2af84b1e-32c8-42b7-82bc-daa82404023b": true,
		"10dae51f-b6af-4016-8d66-8c2a99b929b3": true,
	}

	if restrictedIDs[bag.AuthorizationPolicy.GuestUserRoleID] {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Guest user access restrictions are configured appropriately",
			Evidence: map[string]any{
				"guest_user_role_id": bag.AuthorizationPolicy.GuestUserRoleID,
			},
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Guest user access is not restricted (set to same as member users or unknown)",
		Evidence: map[string]any{
			"current_guest_role_id": bag.AuthorizationPolicy.GuestUserRoleID,
		},
	}, nil
}

// 5.1.6.3: Ensure guest invites are restricted to admin roles
func checkGuestInvitesRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthorizationPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authorization policy not available",
		}, nil
	}

	// allowInvitesFrom should be "adminsAndGuestInviters" or "none" for CIS compliance.
	// "everyone" or "adminsGuestInvitersAndAllMembers" are too permissive.
	switch strings.ToLower(bag.AuthorizationPolicy.AllowInvitesFrom) {
	case "adminsandguestinviters", "none":
		return &checks.CheckResult{
			Passed:  true,
			Message: "Guest invitations are restricted (allowInvitesFrom=" + bag.AuthorizationPolicy.AllowInvitesFrom + ")",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Guest invitations are not restricted to admin roles",
		Evidence: map[string]any{
			"allowInvitesFrom": bag.AuthorizationPolicy.AllowInvitesFrom,
		},
	}, nil
}

// 5.1.8.1: Ensure password hash sync is enabled for hybrid deployments
func checkPasswordHashSyncEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.OnPremSyncSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "On-premises sync settings not available",
		}, nil
	}

	// If on-prem sync is not enabled, this check is not applicable (cloud-only tenant)
	if !bag.OnPremSyncSettings.OnPremisesSyncEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "On-premises sync is not enabled (cloud-only tenant); password hash sync check not applicable",
		}, nil
	}

	if bag.OnPremSyncSettings.PasswordHashSyncEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Password hash sync is enabled for hybrid deployment",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Password hash sync is not enabled for hybrid deployment",
		Evidence: map[string]any{
			"onPremisesSyncEnabled":   true,
			"passwordHashSyncEnabled": false,
		},
	}, nil
}

// ============================================================================
// User-level checks
// ============================================================================

// 5.2.3.4: Ensure users are MFA capable (all users have registered MFA methods)
func checkUsersAreMFACapable(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.CredentialUserRegistrationDetails) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Credential user registration details not available",
		}, nil
	}

	var nonMFACapable []string
	for _, detail := range bag.CredentialUserRegistrationDetails {
		if !detail.IsMfaCapable {
			nonMFACapable = append(nonMFACapable, detail.UserPrincipalName)
		}
	}

	if len(nonMFACapable) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("All %d users are MFA capable", len(bag.CredentialUserRegistrationDetails)),
		}, nil
	}

	// Cap the evidence list to avoid huge payloads
	displayed := nonMFACapable
	if len(displayed) > 20 {
		displayed = displayed[:20]
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d of %d users are not MFA capable", len(nonMFACapable), len(bag.CredentialUserRegistrationDetails)),
		Evidence: map[string]any{
			"non_mfa_capable_users": displayed,
			"total_non_mfa_capable": len(nonMFACapable),
		},
	}, nil
}

// ============================================================================
// Admin identity checks (CIS section 1)
// ============================================================================

// 1.1.1: Ensure admin users are cloud-only (not synced from on-premises)
func checkAdminUsersCloudOnly(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	adminUserIDs := getAdminUserIDs(bag)
	if len(adminUserIDs) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No admin role members found; cannot evaluate",
		}, nil
	}

	userMap := buildUserMap(bag)
	var syncedAdmins []string

	for userID := range adminUserIDs {
		user, exists := userMap[userID]
		if !exists {
			continue
		}
		if user.OnPremisesSyncEnabled != nil && *user.OnPremisesSyncEnabled {
			syncedAdmins = append(syncedAdmins, user.UserPrincipalName)
		}
	}

	if len(syncedAdmins) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "All admin users are cloud-only accounts",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d admin user(s) are synced from on-premises", len(syncedAdmins)),
		Evidence: map[string]any{
			"synced_admin_users": syncedAdmins,
		},
	}, nil
}

// 1.1.2: Ensure break-glass (emergency access) accounts have FIDO2 security keys
func checkBreakGlassHasFIDO2(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	// Identify break-glass accounts by convention: display name or UPN contains "break glass",
	// "emergency", or "breakglass" (case-insensitive).
	var breakGlassUsers []databag.User
	for _, user := range bag.Users {
		nameLower := strings.ToLower(user.DisplayName)
		upnLower := strings.ToLower(user.UserPrincipalName)
		if strings.Contains(nameLower, "break glass") || strings.Contains(nameLower, "breakglass") ||
			strings.Contains(nameLower, "emergency") ||
			strings.Contains(upnLower, "breakglass") || strings.Contains(upnLower, "emergency") {
			breakGlassUsers = append(breakGlassUsers, user)
		}
	}

	if len(breakGlassUsers) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No break-glass / emergency access accounts found",
		}, nil
	}

	var missingFIDO2 []string
	for _, user := range breakGlassUsers {
		hasFIDO2 := false
		for _, method := range user.AuthMethods {
			if strings.EqualFold(method, "fido2") {
				hasFIDO2 = true
				break
			}
		}
		if !hasFIDO2 {
			missingFIDO2 = append(missingFIDO2, user.UserPrincipalName)
		}
	}

	if len(missingFIDO2) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("All %d break-glass account(s) have FIDO2 security keys", len(breakGlassUsers)),
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("%d of %d break-glass account(s) missing FIDO2 security key", len(missingFIDO2), len(breakGlassUsers)),
		Evidence: map[string]any{
			"accounts_missing_fido2": missingFIDO2,
		},
	}, nil
}

// 1.1.3: Ensure between 2 and 4 Global Administrators are configured
func checkGlobalAdminCount(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	var globalAdminMembers []string
	for _, role := range bag.DirectoryRoles {
		if role.RoleTemplateID == globalAdminRoleTemplateID {
			globalAdminMembers = role.Members
			break
		}
	}

	count := len(globalAdminMembers)
	if count >= 2 && count <= 4 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("%d Global Administrators configured (within recommended 2-4)", count),
		}, nil
	}

	msg := fmt.Sprintf("%d Global Administrators configured (recommended: 2-4)", count)
	if count < 2 {
		msg = fmt.Sprintf("Only %d Global Administrator(s) configured; at least 2 recommended for redundancy", count)
	} else {
		msg = fmt.Sprintf("%d Global Administrators configured; no more than 4 recommended to reduce attack surface", count)
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    msg,
		Evidence: map[string]any{
			"global_admin_count":   count,
			"global_admin_members": globalAdminMembers,
		},
	}, nil
}

// ============================================================================
// New CIS v6.0 Entra checks
// ============================================================================

// 5.1.2.2: Ensure third-party integrated apps are not allowed
func checkThirdPartyIntegratedAppsBlocked(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthorizationPolicy == nil || bag.AuthorizationPolicy.DefaultUserRolePermissions == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authorization policy or default user role permissions not available",
		}, nil
	}

	perms := bag.AuthorizationPolicy.DefaultUserRolePermissions
	if !perms.AllowedToCreateApps {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Third-party integrated apps are not allowed (users cannot create apps)",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Third-party integrated apps are allowed (users can create apps)",
		Evidence: map[string]any{
			"allowedToCreateApps": perms.AllowedToCreateApps,
		},
	}, nil
}

// 5.1.3.2: Ensure users cannot create security groups
func checkUsersCannotCreateSecurityGroups(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthorizationPolicy == nil || bag.AuthorizationPolicy.DefaultUserRolePermissions == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authorization policy or default user role permissions not available",
		}, nil
	}

	if !bag.AuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Users cannot create security groups",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Users are allowed to create security groups",
		Evidence: map[string]any{
			"allowedToCreateSecurityGroups": true,
		},
	}, nil
}

// 5.1.4.1: Ensure device join to Entra is restricted
func checkDeviceJoinRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.DeviceRegistrationPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Device registration policy not available",
		}, nil
	}

	if !bag.DeviceRegistrationPolicy.AllUsersCanJoin {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Device join to Entra is restricted (not all users can join devices)",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "All users can join devices to Entra (should be restricted)",
		Evidence: map[string]any{
			"allUsersCanJoin": true,
		},
	}, nil
}

// 5.1.4.2: Ensure maximum number of devices per user is limited
func checkMaxDevicesPerUser(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.DeviceRegistrationPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Device registration policy not available",
		}, nil
	}

	// A reasonable limit; unlimited (0 or very high) should fail
	if bag.DeviceRegistrationPolicy.MaxDevicesPerUser > 0 && bag.DeviceRegistrationPolicy.MaxDevicesPerUser <= 20 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("Maximum devices per user is limited to %d", bag.DeviceRegistrationPolicy.MaxDevicesPerUser),
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Maximum devices per user is not appropriately limited",
		Evidence: map[string]any{
			"maxDevicesPerUser": bag.DeviceRegistrationPolicy.MaxDevicesPerUser,
		},
	}, nil
}

// 5.1.4.3: Ensure Global Administrator role is not added as local admin during Entra join
func checkGANotLocalAdmin(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.DeviceRegistrationPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Device registration policy not available",
		}, nil
	}

	if !bag.DeviceRegistrationPolicy.GlobalAdminAsLocalAdmin {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Global Administrator role is not added as local admin during Entra join",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Global Administrator role is added as local admin during Entra join",
		Evidence: map[string]any{
			"globalAdminAsLocalAdmin": true,
		},
	}, nil
}

// 5.1.4.4: Ensure additional local admin assignment is limited during Entra join
func checkAdditionalLocalAdminsLimited(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.DeviceRegistrationPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Device registration policy not available",
		}, nil
	}

	if !bag.DeviceRegistrationPolicy.AdditionalLocalAdmins {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Additional local admin assignment is limited during Entra join",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Additional local admins can be assigned during Entra join",
		Evidence: map[string]any{
			"additionalLocalAdmins": true,
		},
	}, nil
}

// 5.1.4.5: Ensure LAPS is enabled
func checkLAPSEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.LAPSSettings == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "LAPS settings not available",
		}, nil
	}

	if bag.LAPSSettings.Enabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "LAPS (Local Administrator Password Solution) is enabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "LAPS (Local Administrator Password Solution) is not enabled",
		Evidence: map[string]any{
			"enabled": false,
		},
	}, nil
}

// 5.1.4.6: Ensure users are restricted from recovering BitLocker keys for their owned devices
func checkBitlockerKeyRecoveryRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthorizationPolicy == nil || bag.AuthorizationPolicy.DefaultUserRolePermissions == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authorization policy or default user role permissions not available",
		}, nil
	}

	if !bag.AuthorizationPolicy.DefaultUserRolePermissions.AllowedToReadBitlockerKeysForOwnedDevice {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Users are restricted from recovering BitLocker keys for their owned devices",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Users can recover BitLocker keys for their owned devices",
		Evidence: map[string]any{
			"allowedToReadBitlockerKeysForOwnedDevice": true,
		},
	}, nil
}

// 5.2.3.2: Ensure a custom banned passwords list is used
func checkCustomBannedPasswords(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.PasswordPolicies == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Password policies not available",
		}, nil
	}

	if bag.PasswordPolicies.BannedPasswordsEnabled && len(bag.PasswordPolicies.CustomBannedPasswords) > 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("Custom banned passwords list is enabled with %d entries", len(bag.PasswordPolicies.CustomBannedPasswords)),
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Custom banned passwords list is not configured or empty",
		Evidence: map[string]any{
			"bannedPasswordsEnabled": bag.PasswordPolicies.BannedPasswordsEnabled,
			"customBannedCount":      len(bag.PasswordPolicies.CustomBannedPasswords),
		},
	}, nil
}

// 5.2.3.3: Ensure password protection is enabled for on-premises Active Directory
func checkPasswordProtectionOnPrem(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.PasswordPolicies == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Password policies not available",
		}, nil
	}

	if bag.PasswordPolicies.EnableBannedPasswordCheckOnPrem {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Password protection is enabled for on-premises Active Directory",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Password protection is not enabled for on-premises Active Directory",
		Evidence: map[string]any{
			"enableBannedPasswordCheckOnPrem": false,
		},
	}, nil
}

// 5.2.3.5: Ensure weak authentication methods (SMS, voice, email OTP) are disabled
func checkWeakAuthMethodsDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthMethodsPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authentication methods policy not available",
		}, nil
	}

	weakMethods := map[string]bool{"sms": true, "voice": true, "email": true}
	var enabledWeakMethods []string
	for _, config := range bag.AuthMethodsPolicy.AuthMethodConfigs {
		methodLower := strings.ToLower(config.MethodType)
		if weakMethods[methodLower] && strings.EqualFold(config.State, "enabled") {
			enabledWeakMethods = append(enabledWeakMethods, config.MethodType)
		}
	}

	if len(enabledWeakMethods) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Weak authentication methods (SMS, voice, email OTP) are disabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Weak authentication methods are enabled: " + strings.Join(enabledWeakMethods, ", "),
		Evidence: map[string]any{
			"enabled_weak_methods": enabledWeakMethods,
		},
	}, nil
}

// 5.3.2: Ensure access reviews for guest users are configured
func checkAccessReviewsForGuests(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.AccessReviews) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No access reviews configured",
		}, nil
	}

	for _, review := range bag.AccessReviews {
		if review.Enabled && strings.EqualFold(review.Scope, "Guest") {
			return &checks.CheckResult{
				Passed:  true,
				Message: "Access reviews for guest users are configured",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No access review configured for guest users",
		Evidence: map[string]any{
			"total_reviews": len(bag.AccessReviews),
		},
	}, nil
}

// ============================================================================
// Beyond-CIS / Prowler extra checks
// ============================================================================

// EXTRA.1: Ensure SMS and Voice authentication methods are disabled
func checkSMSVoiceAuthDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.AuthMethodsPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Authentication methods policy not available",
		}, nil
	}

	var enabledWeakMethods []string
	for _, config := range bag.AuthMethodsPolicy.AuthMethodConfigs {
		methodLower := strings.ToLower(config.MethodType)
		if (methodLower == "sms" || methodLower == "voice") && strings.EqualFold(config.State, "enabled") {
			enabledWeakMethods = append(enabledWeakMethods, config.MethodType)
		}
	}

	if len(enabledWeakMethods) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "SMS and Voice authentication methods are disabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Weak authentication methods are enabled: " + strings.Join(enabledWeakMethods, ", "),
		Evidence: map[string]any{
			"enabled_weak_methods": enabledWeakMethods,
		},
	}, nil
}

// EXTRA.2: Ensure Conditional Access policies cover all cloud applications
// Verifies that at least one enabled CA policy with MFA targets "All" applications.
func checkCACoversAllCloudApps(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	for _, policy := range bag.ConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}
		if !includesAllApps(policy) {
			continue
		}
		// Must have meaningful grant controls (MFA, compliant device, or block)
		if requiresMFA(policy) || requiresCompliantDevice(policy) {
			return &checks.CheckResult{
				Passed:  true,
				Message: "CA policy '" + policy.DisplayName + "' covers all cloud applications with MFA or device compliance",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No enabled CA policy with MFA or device compliance covers all cloud applications",
		Evidence: map[string]any{
			"policies_checked": len(bag.ConditionalAccessPolicies),
		},
	}, nil
}

// ============================================================================
// Helper functions for check evaluation
// ============================================================================

// includesAdminRoles checks if a CA policy targets admin roles.
// Returns true if the policy includes "All" roles or includes known admin role template IDs.
func includesAdminRoles(policy databag.ConditionalAccessPolicy) bool {
	for _, role := range policy.IncludeRoles {
		if strings.EqualFold(role, "All") {
			return true
		}
		if _, isAdmin := adminRoleTemplateIDs[role]; isAdmin {
			return true
		}
	}
	return false
}

// includesAllUsers checks if a CA policy targets all users.
func includesAllUsers(policy databag.ConditionalAccessPolicy) bool {
	return containsStr(policy.IncludeUsers, "All")
}

// includesAllApps checks if a CA policy targets all cloud apps.
func includesAllApps(policy databag.ConditionalAccessPolicy) bool {
	return containsStr(policy.IncludeApplications, "All")
}

// requiresMFA checks if a CA policy requires multifactor authentication.
func requiresMFA(policy databag.ConditionalAccessPolicy) bool {
	return containsStr(policy.BuiltInControls, "mfa")
}

// blocksAccess checks if a CA policy blocks access.
func blocksAccess(policy databag.ConditionalAccessPolicy) bool {
	return containsStr(policy.BuiltInControls, "block")
}

// targetsLegacyClients checks if a CA policy targets legacy authentication clients.
func targetsLegacyClients(policy databag.ConditionalAccessPolicy) bool {
	hasLegacy := false
	for _, cat := range policy.ClientAppTypes {
		switch strings.ToLower(cat) {
		case "exchangeactivesync", "other":
			hasLegacy = true
		}
	}
	return hasLegacy
}

// requiresPhishingResistantMFA checks if the policy requires phishing-resistant MFA
// via an authentication strength that only allows phishing-resistant methods.
func requiresPhishingResistantMFA(policy databag.ConditionalAccessPolicy) bool {
	if policy.AuthenticationStrength == nil {
		return false
	}
	// Check if the authentication strength name indicates phishing-resistant,
	// or if allowed combinations only contain phishing-resistant methods.
	nameLower := strings.ToLower(policy.AuthenticationStrength.DisplayName)
	if strings.Contains(nameLower, "phishing-resistant") || strings.Contains(nameLower, "phishingresistant") {
		return true
	}
	// Check allowed combinations for phishing-resistant-only methods
	phishingResistant := map[string]bool{
		"fido2":                     true,
		"windowshelloforbusiness":   true,
		"x509certificatemultifactor": true,
	}
	if len(policy.AuthenticationStrength.AllowedCombinations) == 0 {
		return false
	}
	for _, combo := range policy.AuthenticationStrength.AllowedCombinations {
		if !phishingResistant[strings.ToLower(combo)] {
			return false
		}
	}
	return true
}

// requiresCompliantDevice checks if the policy requires a compliant or hybrid-joined device.
func requiresCompliantDevice(policy databag.ConditionalAccessPolicy) bool {
	return containsStr(policy.BuiltInControls, "compliantDevice") ||
		containsStr(policy.BuiltInControls, "domainJoinedDevice")
}

// targetsUserActionMFARegistration checks if a CA policy targets the MFA registration user action.
func targetsUserActionMFARegistration(policy databag.ConditionalAccessPolicy) bool {
	for _, action := range policy.IncludeUserActions {
		if strings.EqualFold(action, "urn:user:registersecurityinfo") ||
			strings.EqualFold(action, "registerSecurityInformation") {
			return true
		}
	}
	return false
}

// targetsDeviceCodeFlow checks if a CA policy targets the device code authentication flow.
func targetsDeviceCodeFlow(policy databag.ConditionalAccessPolicy) bool {
	for _, method := range policy.TransferMethods {
		if strings.EqualFold(method, "deviceCodeFlow") {
			return true
		}
	}
	// Also check clientAppTypes for "deviceCode" (older API representation)
	for _, cat := range policy.ClientAppTypes {
		if strings.EqualFold(cat, "deviceCode") {
			return true
		}
	}
	return false
}

// isDynamicGroup checks if a group uses dynamic membership.
func isDynamicGroup(group databag.Group) bool {
	for _, gt := range group.GroupTypes {
		if strings.EqualFold(gt, "DynamicMembership") {
			return true
		}
	}
	return false
}

// getAdminUserIDs returns a set of user IDs that are members of any admin role.
func getAdminUserIDs(bag *databag.M365DataBag) map[string]bool {
	result := make(map[string]bool)
	for _, role := range bag.DirectoryRoles {
		if _, isAdmin := adminRoleTemplateIDs[role.RoleTemplateID]; isAdmin {
			for _, memberID := range role.Members {
				result[memberID] = true
			}
		}
	}
	return result
}

// buildUserMap creates a map from user ID to User for quick lookups.
func buildUserMap(bag *databag.M365DataBag) map[string]databag.User {
	m := make(map[string]databag.User, len(bag.Users))
	for _, u := range bag.Users {
		m[u.ID] = u
	}
	return m
}
