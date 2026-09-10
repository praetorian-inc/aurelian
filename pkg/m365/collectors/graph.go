// Package collectors implements data collection from M365 APIs into the DataBag.
package collectors

import (
	"context"
	"fmt"
	"log/slog"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

// GraphCollector fetches data from the Microsoft Graph API into the DataBag.
type GraphCollector struct {
	client *msgraphsdk.GraphServiceClient
}

// NewGraphCollector creates a new GraphCollector.
func NewGraphCollector(client *msgraphsdk.GraphServiceClient) *GraphCollector {
	return &GraphCollector{client: client}
}

// CollectEntraData fetches all Entra ID data needed by CIS Entra checks.
func (c *GraphCollector) CollectEntraData(ctx context.Context, bag *databag.M365DataBag) error {
	// Collect conditional access policies
	if err := c.collectConditionalAccessPolicies(ctx, bag); err != nil {
		slog.Warn("failed to collect conditional access policies", "error", err)
	}

	// Collect authorization policy
	if err := c.collectAuthorizationPolicy(ctx, bag); err != nil {
		slog.Warn("failed to collect authorization policy", "error", err)
	}

	// Collect directory roles
	if err := c.collectDirectoryRoles(ctx, bag); err != nil {
		slog.Warn("failed to collect directory roles", "error", err)
	}

	// Collect auth methods policy
	if err := c.collectAuthMethodsPolicy(ctx, bag); err != nil {
		slog.Warn("failed to collect auth methods policy", "error", err)
	}

	return nil
}

func (c *GraphCollector) collectConditionalAccessPolicies(ctx context.Context, bag *databag.M365DataBag) error {
	result, err := c.client.Identity().ConditionalAccess().Policies().Get(ctx, nil)
	if err != nil {
		return fmt.Errorf("listing CA policies: %w", err)
	}
	if result == nil {
		return nil
	}

	pageIterator, err := msgraphcore.NewPageIterator[models.ConditionalAccessPolicyable](
		result,
		c.client.GetAdapter(),
		models.CreateConditionalAccessPolicyCollectionResponseFromDiscriminatorValue,
	)
	if err != nil {
		return fmt.Errorf("creating page iterator: %w", err)
	}

	err = pageIterator.Iterate(ctx, func(policy models.ConditionalAccessPolicyable) bool {
		if policy != nil {
			bag.ConditionalAccessPolicies = append(bag.ConditionalAccessPolicies, convertCAPolicy(policy))
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("iterating CA policies: %w", err)
	}

	slog.Info("collected conditional access policies", "count", len(bag.ConditionalAccessPolicies))
	return nil
}

func convertCAPolicy(p models.ConditionalAccessPolicyable) databag.ConditionalAccessPolicy {
	policy := databag.ConditionalAccessPolicy{
		ID:          derefStr(p.GetId()),
		DisplayName: derefStr(p.GetDisplayName()),
		State:       convertPolicyState(p.GetState()),
	}

	if c := p.GetConditions(); c != nil {
		if u := c.GetUsers(); u != nil {
			policy.IncludeUsers = u.GetIncludeUsers()
			policy.ExcludeUsers = u.GetExcludeUsers()
			policy.IncludeGroups = u.GetIncludeGroups()
			policy.ExcludeGroups = u.GetExcludeGroups()
			policy.IncludeRoles = u.GetIncludeRoles()
			policy.ExcludeRoles = u.GetExcludeRoles()
		}
		if a := c.GetApplications(); a != nil {
			policy.IncludeApplications = a.GetIncludeApplications()
			policy.ExcludeApplications = a.GetExcludeApplications()
		}
		policy.ClientAppTypes = convertClientAppTypes(c.GetClientAppTypes())
		policy.SignInRiskLevels = convertRiskLevels(c.GetSignInRiskLevels())
		policy.UserRiskLevels = convertRiskLevels(c.GetUserRiskLevels())
	}

	if gc := p.GetGrantControls(); gc != nil {
		if gc.GetOperator() != nil {
			policy.GrantOperator = *gc.GetOperator()
		}
		policy.BuiltInControls = convertGrantControls(gc.GetBuiltInControls())
	}

	return policy
}

func (c *GraphCollector) collectAuthorizationPolicy(ctx context.Context, bag *databag.M365DataBag) error {
	result, err := c.client.Policies().AuthorizationPolicy().Get(ctx, nil)
	if err != nil {
		return fmt.Errorf("getting authorization policy: %w", err)
	}
	if result == nil {
		return nil
	}

	policy := &databag.AuthorizationPolicy{
		ID: derefStr(result.GetId()),
	}

	if v := result.GetAllowInvitesFrom(); v != nil {
		policy.AllowInvitesFrom = v.String()
	}
	if v := result.GetAllowedToSignUpEmailBasedSubscriptions(); v != nil {
		policy.AllowedToSignUpEmailBasedSubscriptions = *v
	}
	if v := result.GetAllowedToUseSSPR(); v != nil {
		policy.AllowedToUseSSPR = *v
	}
	if v := result.GetAllowEmailVerifiedUsersToJoinOrganization(); v != nil {
		policy.AllowEmailVerifiedUsersToJoinOrganization = *v
	}
	if v := result.GetBlockMsolPowerShell(); v != nil {
		policy.BlockMsolPowerShell = *v
	}
	if v := result.GetGuestUserRoleId(); v != nil {
		policy.GuestUserRoleID = v.String()
	}

	if dur := result.GetDefaultUserRolePermissions(); dur != nil {
		perms := &databag.DefaultUserRolePermissions{}
		if v := dur.GetAllowedToCreateApps(); v != nil {
			perms.AllowedToCreateApps = *v
		}
		if v := dur.GetAllowedToCreateSecurityGroups(); v != nil {
			perms.AllowedToCreateSecurityGroups = *v
		}
		if v := dur.GetAllowedToCreateTenants(); v != nil {
			perms.AllowedToCreateTenants = *v
		}
		if v := dur.GetAllowedToReadOtherUsers(); v != nil {
			perms.AllowedToReadOtherUsers = *v
		}
		policy.DefaultUserRolePermissions = perms
	}

	bag.AuthorizationPolicy = policy
	slog.Info("collected authorization policy")
	return nil
}

func (c *GraphCollector) collectDirectoryRoles(ctx context.Context, bag *databag.M365DataBag) error {
	result, err := c.client.DirectoryRoles().Get(ctx, nil)
	if err != nil {
		return fmt.Errorf("listing directory roles: %w", err)
	}
	if result == nil {
		return nil
	}

	for _, role := range result.GetValue() {
		dr := databag.DirectoryRole{
			ID:             derefStr(role.GetId()),
			DisplayName:    derefStr(role.GetDisplayName()),
			RoleTemplateID: derefStr(role.GetRoleTemplateId()),
		}

		// Get members for each role
		members, err := c.client.DirectoryRoles().ByDirectoryRoleId(dr.ID).Members().Get(ctx, nil)
		if err != nil {
			slog.Warn("failed to get role members", "role", dr.DisplayName, "error", err)
		} else if members != nil {
			for _, m := range members.GetValue() {
				if m.GetId() != nil {
					dr.Members = append(dr.Members, *m.GetId())
				}
			}
		}

		bag.DirectoryRoles = append(bag.DirectoryRoles, dr)
	}

	slog.Info("collected directory roles", "count", len(bag.DirectoryRoles))
	return nil
}

func (c *GraphCollector) collectAuthMethodsPolicy(ctx context.Context, bag *databag.M365DataBag) error {
	result, err := c.client.Policies().AuthenticationMethodsPolicy().Get(ctx, nil)
	if err != nil {
		return fmt.Errorf("getting auth methods policy: %w", err)
	}
	if result == nil {
		return nil
	}

	policy := &databag.AuthMethodsPolicy{
		ID: derefStr(result.GetId()),
	}

	if re := result.GetRegistrationEnforcement(); re != nil {
		if campaign := re.GetAuthenticationMethodsRegistrationCampaign(); campaign != nil {
			enforcement := &databag.RegistrationEnforcement{
				AuthenticationMethodsRegistrationCampaign: &databag.MFARegistrationCampaign{},
			}
			if state := campaign.GetState(); state != nil {
				enforcement.AuthenticationMethodsRegistrationCampaign.State = state.String()
			}
			policy.RegistrationEnforcement = enforcement
		}
	}

	if configs := result.GetAuthenticationMethodConfigurations(); configs != nil {
		for _, cfg := range configs {
			amc := databag.AuthMethodConfiguration{
				ID: derefStr(cfg.GetId()),
			}
			if s := cfg.GetState(); s != nil {
				amc.State = s.String()
			}
			amc.MethodType = derefStr(cfg.GetOdataType())
			policy.AuthMethodConfigs = append(policy.AuthMethodConfigs, amc)
		}
	}

	bag.AuthMethodsPolicy = policy
	slog.Info("collected auth methods policy")
	return nil
}

// Helper functions

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func convertPolicyState(state *models.ConditionalAccessPolicyState) string {
	if state == nil {
		return "unknown"
	}
	switch *state {
	case models.ENABLED_CONDITIONALACCESSPOLICYSTATE:
		return "enabled"
	case models.DISABLED_CONDITIONALACCESSPOLICYSTATE:
		return "disabled"
	case models.ENABLEDFORREPORTINGBUTNOTENFORCED_CONDITIONALACCESSPOLICYSTATE:
		return "enabledForReportingButNotEnforced"
	default:
		return "unknown"
	}
}

func convertClientAppTypes(apps []models.ConditionalAccessClientApp) []string {
	result := make([]string, 0, len(apps))
	for _, app := range apps {
		switch app {
		case models.ALL_CONDITIONALACCESSCLIENTAPP:
			result = append(result, "all")
		case models.BROWSER_CONDITIONALACCESSCLIENTAPP:
			result = append(result, "browser")
		case models.MOBILEAPPSANDDESKTOPCLIENTS_CONDITIONALACCESSCLIENTAPP:
			result = append(result, "mobileAppsAndDesktopClients")
		case models.EXCHANGEACTIVESYNC_CONDITIONALACCESSCLIENTAPP:
			result = append(result, "exchangeActiveSync")
		case models.OTHER_CONDITIONALACCESSCLIENTAPP:
			result = append(result, "other")
		}
	}
	return result
}

func convertGrantControls(controls []models.ConditionalAccessGrantControl) []string {
	result := make([]string, 0, len(controls))
	for _, ctrl := range controls {
		switch ctrl {
		case models.BLOCK_CONDITIONALACCESSGRANTCONTROL:
			result = append(result, "block")
		case models.MFA_CONDITIONALACCESSGRANTCONTROL:
			result = append(result, "mfa")
		case models.COMPLIANTDEVICE_CONDITIONALACCESSGRANTCONTROL:
			result = append(result, "compliantDevice")
		case models.DOMAINJOINEDDEVICE_CONDITIONALACCESSGRANTCONTROL:
			result = append(result, "domainJoinedDevice")
		case models.APPROVEDAPPLICATION_CONDITIONALACCESSGRANTCONTROL:
			result = append(result, "approvedApplication")
		case models.COMPLIANTAPPLICATION_CONDITIONALACCESSGRANTCONTROL:
			result = append(result, "compliantApplication")
		case models.PASSWORDCHANGE_CONDITIONALACCESSGRANTCONTROL:
			result = append(result, "passwordChange")
		}
	}
	return result
}

func convertRiskLevels(risks []models.RiskLevel) []string {
	result := make([]string, 0, len(risks))
	for _, risk := range risks {
		switch risk {
		case models.LOW_RISKLEVEL:
			result = append(result, "low")
		case models.MEDIUM_RISKLEVEL:
			result = append(result, "medium")
		case models.HIGH_RISKLEVEL:
			result = append(result, "high")
		case models.NONE_RISKLEVEL:
			result = append(result, "none")
		}
	}
	return result
}
