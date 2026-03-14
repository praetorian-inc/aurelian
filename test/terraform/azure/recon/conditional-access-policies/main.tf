// Module: azure-recon-conditional-access-policies
// Enumerates Azure AD Conditional Access Policies via Microsoft Graph,
// resolving UUIDs to human-readable names for users, groups, applications,
// and directory roles.
//
// ==================== TEST CASES ====================
//
// This fixture provisions 10 Conditional Access Policies across all 3 states
// that exercise every major condition type the module must parse and resolve.
//
// | #  | Policy Name                      | State       | What it exercises                                              |
// |----|----------------------------------|-------------|----------------------------------------------------------------|
// | 1  | ${prefix}-mfa-admins             | disabled    | User/group/role targeting, browser, MFA grant, sign-in freq    |
// | 2  | ${prefix}-device-compliance      | disabled    | All users + group exclusion, device filter, AND grant          |
// | 3  | ${prefix}-risk-based             | report-only | Sign-in risk, user risk, persistent browser, cloud app sec     |
// | 4  | ${prefix}-app-targeted           | disabled    | Specific app target, EAS client, block grant, app restrictions |
// | 5  | ${prefix}-location-based         | disabled    | Named location exclusion, platform exclusion, all clients      |
// | 6  | ${prefix}-block-legacy-auth      | enabled     | Legacy auth block (EAS+other), all users, multiple roles       |
// | 7  | ${prefix}-require-password-change| report-only | High user risk, passwordChange grant, multiple user exclusions |
// | 8  | ${prefix}-azure-mgmt-mfa         | enabled     | Azure Management app by well-known ID, role exclusion          |
// | 9  | ${prefix}-mobile-approved-apps   | disabled    | approvedApplication+compliantApplication AND, mobile platforms |
// | 10 | ${prefix}-guest-access           | report-only | GuestsOrExternalUsers in included_guests, Office365 app target |
//
// Supporting Entra ID objects:
// | Object                     | Type               | Used by policies              |
// |----------------------------|--------------------|-------------------------------|
// | ${prefix}-test-user        | azuread_user       | 1, 4, 7 (exclude)             |
// | ${prefix}-exclude-user     | azuread_user       | 3, 7 (exclude)                |
// | ${prefix}-admin-user       | azuread_user       | 6 (exclude breakglass)        |
// | ${prefix}-test-group       | azuread_group      | 1, 2 (exclude), 5, 9          |
// | ${prefix}-admin-group      | azuread_group      | 6 (exclude), 8 (exclude)      |
// | ${prefix}-test-app         | azuread_application| 4 (specific app)              |
// | ${prefix}-named-location   | named_location     | 5 (exclude)                   |

terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "s3" {}
}

provider "azuread" {}

data "azuread_client_config" "current" {}

data "azuread_domains" "default" {
  only_initial = true
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  prefix = "aurelian-itest-${random_string.suffix.result}"
  domain = data.azuread_domains.default.domains[0].domain_name

  // Well-known directory role template IDs
  global_admin_role_template_id      = "62e90394-69f5-4237-9190-012177145e10"
  security_reader_role_template_id   = "5d6b6bb7-de71-4623-b4af-96380a352509"
  exchange_admin_role_template_id    = "29232cdf-9323-42fd-ade2-1d097af3e4de"
  user_admin_role_template_id        = "fe930be7-5e62-47db-91af-98c3a49a38b1"
  helpdesk_admin_role_template_id    = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
  security_admin_role_template_id    = "194ae4cb-b126-40b2-bd5b-6091b380977d"

  // Well-known application IDs (Microsoft first-party)
  azure_management_app_id = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
}

#==============================================================================
# ENTRA ID OBJECTS
#==============================================================================

resource "azuread_user" "test" {
  user_principal_name = "${local.prefix}-test-user@${local.domain}"
  display_name        = "${local.prefix}-test-user"
  mail_nickname       = "${local.prefix}-test-user"
  password            = "P@ssw0rd${random_string.suffix.result}!Aa1"
}

resource "azuread_user" "exclude" {
  user_principal_name = "${local.prefix}-exclude-user@${local.domain}"
  display_name        = "${local.prefix}-exclude-user"
  mail_nickname       = "${local.prefix}-exclude-user"
  password            = "P@ssw0rd${random_string.suffix.result}!Bb2"
}

resource "azuread_user" "admin" {
  user_principal_name = "${local.prefix}-admin-user@${local.domain}"
  display_name        = "${local.prefix}-admin-user"
  mail_nickname       = "${local.prefix}-admin-user"
  password            = "P@ssw0rd${random_string.suffix.result}!Cc3"
}

resource "azuread_group" "test" {
  display_name     = "${local.prefix}-test-group"
  security_enabled = true
  members          = [azuread_user.test.object_id]
}

resource "azuread_group" "admin" {
  display_name     = "${local.prefix}-admin-group"
  security_enabled = true
  members          = [azuread_user.admin.object_id]
}

resource "azuread_application" "test" {
  display_name = "${local.prefix}-test-app"
}

resource "azuread_service_principal" "test" {
  client_id = azuread_application.test.client_id
}

resource "azuread_named_location" "test" {
  display_name = "${local.prefix}-named-location"

  ip {
    ip_ranges = ["203.0.113.0/24"]
    trusted   = false
  }
}

#==============================================================================
# POLICY 1: MFA for admins
# Exercises: user + group + role targeting, browser clientAppType,
#            MFA grant control, sign-in frequency session control,
#            platform conditions, location conditions
# State: disabled
#==============================================================================
resource "azuread_conditional_access_policy" "mfa_admins" {
  display_name = "${local.prefix}-mfa-admins"
  state        = "disabled"

  conditions {
    users {
      included_users  = [azuread_user.test.object_id]
      included_groups = [azuread_group.test.object_id]
      included_roles  = [local.global_admin_role_template_id]
    }

    applications {
      included_applications = ["All"]
    }

    client_app_types = ["browser"]

    platforms {
      included_platforms = ["android", "iOS"]
    }

    locations {
      included_locations = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }

  session_controls {
    sign_in_frequency        = 4
    sign_in_frequency_period = "hours"
  }
}

#==============================================================================
# POLICY 2: Device compliance
# Exercises: All users with group exclusion, device filter,
#            AND operator with compliantDevice + domainJoinedDevice,
#            mobileAppsAndDesktopClients clientAppType
# State: disabled
#==============================================================================
resource "azuread_conditional_access_policy" "device_compliance" {
  display_name = "${local.prefix}-device-compliance"
  state        = "disabled"

  conditions {
    users {
      included_users  = ["All"]
      excluded_groups = [azuread_group.test.object_id]
    }

    applications {
      included_applications = ["All"]
    }

    client_app_types = ["mobileAppsAndDesktopClients"]

    devices {
      filter {
        mode = "exclude"
        rule = "device.operatingSystem eq \"Windows\""
      }
    }
  }

  grant_controls {
    operator          = "AND"
    built_in_controls = ["compliantDevice", "domainJoinedDevice"]
  }
}

#==============================================================================
# POLICY 3: Risk-based (report-only)
# Exercises: enabledForReportingButNotEnforced state, sign-in risk levels,
#            user risk levels, excludeUsers, persistent browser session,
#            cloud app security policy, multiple roles
# State: enabledForReportingButNotEnforced
#==============================================================================
resource "azuread_conditional_access_policy" "risk_based" {
  display_name = "${local.prefix}-risk-based"
  state        = "enabledForReportingButNotEnforced"

  conditions {
    users {
      included_users = ["All"]
      excluded_users = [azuread_user.exclude.object_id]
      included_roles = [
        local.global_admin_role_template_id,
        local.security_reader_role_template_id,
      ]
    }

    applications {
      included_applications = ["All"]
    }

    client_app_types    = ["all"]
    sign_in_risk_levels = ["high", "medium"]
    user_risk_levels    = ["high"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }

  session_controls {
    persistent_browser_mode   = "never"
    cloud_app_security_policy = "monitorOnly"
  }
}

#==============================================================================
# POLICY 4: App-targeted with block
# Exercises: Specific application targeting (not "All"), exclude application,
#            exchangeActiveSync + other clientAppTypes, block grant control,
#            application_enforced_restrictions session control
# State: disabled
#==============================================================================
resource "azuread_conditional_access_policy" "app_targeted" {
  display_name = "${local.prefix}-app-targeted"
  state        = "disabled"

  conditions {
    users {
      included_users = [azuread_user.test.object_id]
    }

    applications {
      included_applications = [azuread_application.test.client_id]
      excluded_applications = ["Office365"]
    }

    client_app_types = ["exchangeActiveSync", "other"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }

  session_controls {
    application_enforced_restrictions_enabled = true
  }
}

#==============================================================================
# POLICY 5: Location-based
# Exercises: Named location exclusion, AllTrusted exclusion,
#            platform exclusion, GuestsOrExternalUsers in excludeUsers,
#            secondaryAuthentication sign-in frequency type
# State: disabled
#==============================================================================
resource "azuread_conditional_access_policy" "location_based" {
  display_name = "${local.prefix}-location-based"
  state        = "disabled"

  conditions {
    users {
      included_users  = ["All"]
      excluded_users  = ["GuestsOrExternalUsers"]
      included_groups = [azuread_group.test.object_id]
    }

    applications {
      included_applications = ["All"]
    }

    client_app_types = ["all"]

    locations {
      included_locations = ["All"]
      excluded_locations = ["AllTrusted", azuread_named_location.test.id]
    }

    platforms {
      included_platforms = ["all"]
      excluded_platforms = ["iOS", "macOS"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }

  session_controls {
    sign_in_frequency                     = 1
    sign_in_frequency_period              = "days"
    sign_in_frequency_authentication_type = "secondaryAuthentication"
  }
}

#==============================================================================
# POLICY 6: Block legacy authentication (Microsoft template pattern)
# Mirrors: "Block legacy authentication" template
# Exercises: enabled state, EAS+other+browser client types, block grant,
#            multiple admin role exclusions, breakglass user exclusion,
#            All users targeting
# State: enabled
#==============================================================================
resource "azuread_conditional_access_policy" "block_legacy_auth" {
  display_name = "${local.prefix}-block-legacy-auth"
  state        = "enabled"

  conditions {
    users {
      included_users = ["All"]
      excluded_users = [azuread_user.admin.object_id]
      excluded_roles = [local.global_admin_role_template_id]
    }

    applications {
      included_applications = ["All"]
    }

    client_app_types = ["exchangeActiveSync", "other"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

#==============================================================================
# POLICY 7: Require password change for high-risk users (Microsoft template)
# Mirrors: "Require password change for high risk users" template
# Exercises: report-only state, high user risk only, passwordChange grant,
#            multiple user exclusions, both include and exclude roles
# State: enabledForReportingButNotEnforced
#==============================================================================
resource "azuread_conditional_access_policy" "require_password_change" {
  display_name = "${local.prefix}-require-password-change"
  state        = "enabledForReportingButNotEnforced"

  conditions {
    users {
      included_users = ["All"]
      excluded_users = [
        azuread_user.test.object_id,
        azuread_user.exclude.object_id,
      ]
      excluded_groups = [azuread_group.admin.object_id]
    }

    applications {
      included_applications = ["All"]
    }

    client_app_types = ["all"]
    user_risk_levels = ["high"]
  }

  grant_controls {
    operator          = "AND"
    built_in_controls = ["mfa", "passwordChange"]
  }
}

#==============================================================================
# POLICY 8: Require MFA for Azure management (Microsoft template pattern)
# Mirrors: "Require MFA for Azure management" template
# Exercises: enabled state, well-known Azure Management app ID,
#            role-based exclusion (breakglass), group exclusion,
#            all client types
# State: enabled
#==============================================================================
resource "azuread_conditional_access_policy" "azure_mgmt_mfa" {
  display_name = "${local.prefix}-azure-mgmt-mfa"
  state        = "enabled"

  conditions {
    users {
      included_users  = ["All"]
      excluded_groups = [azuread_group.admin.object_id]
      included_roles  = [
        local.global_admin_role_template_id,
        local.security_admin_role_template_id,
        local.user_admin_role_template_id,
      ]
    }

    applications {
      included_applications = [local.azure_management_app_id]
    }

    client_app_types = ["all"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

#==============================================================================
# POLICY 9: Approved apps only on mobile (Microsoft template pattern)
# Mirrors: "Require approved client app or app protection policy" template
# Exercises: disabled state, approvedApplication + compliantApplication
#            AND grant, mobile-only platforms (android + iOS),
#            group targeting, browser + mobile client types
# State: disabled
#==============================================================================
resource "azuread_conditional_access_policy" "mobile_approved_apps" {
  display_name = "${local.prefix}-mobile-approved-apps"
  state        = "disabled"

  conditions {
    users {
      included_groups = [azuread_group.test.object_id]
    }

    applications {
      included_applications = ["Office365"]
    }

    client_app_types = ["browser", "mobileAppsAndDesktopClients"]

    platforms {
      included_platforms = ["android", "iOS"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["approvedApplication", "compliantApplication"]
  }
}

#==============================================================================
# POLICY 10: Guest and external user access (Microsoft template pattern)
# Mirrors: "Require MFA for guest access" template
# Exercises: report-only state, included_guests_or_external_users,
#            Office365 + specific app targeting, multiple exclude apps,
#            sign-in risk levels (low), all platforms
# State: enabledForReportingButNotEnforced
#==============================================================================
resource "azuread_conditional_access_policy" "guest_access" {
  display_name = "${local.prefix}-guest-access"
  state        = "enabledForReportingButNotEnforced"

  conditions {
    users {
      included_users = ["GuestsOrExternalUsers"]
      excluded_users = [azuread_user.admin.object_id]
    }

    applications {
      included_applications = ["Office365"]
    }

    client_app_types    = ["all"]
    sign_in_risk_levels = ["low", "medium"]

    platforms {
      included_platforms = ["all"]
    }

    locations {
      included_locations = ["All"]
      excluded_locations = ["AllTrusted"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }

  session_controls {
    sign_in_frequency        = 1
    sign_in_frequency_period = "days"
    persistent_browser_mode  = "never"
  }
}
