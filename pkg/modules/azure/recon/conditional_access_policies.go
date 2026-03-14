package recon

import (
	"context"
	"fmt"
	"log/slog"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"

	"github.com/praetorian-inc/aurelian/pkg/azure/graphresolver"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AzureConditionalAccessPoliciesModule{})
}

type AzureConditionalAccessPoliciesConfig struct {
	plugin.AzureCommonRecon
}

type AzureConditionalAccessPoliciesModule struct {
	AzureConditionalAccessPoliciesConfig
}

func (m *AzureConditionalAccessPoliciesModule) ID() string          { return "conditional-access-policies" }
func (m *AzureConditionalAccessPoliciesModule) Name() string        { return "Azure Conditional Access Policies" }
func (m *AzureConditionalAccessPoliciesModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureConditionalAccessPoliciesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureConditionalAccessPoliciesModule) OpsecLevel() string  { return "safe" }
func (m *AzureConditionalAccessPoliciesModule) Authors() []string   { return []string{"Praetorian"} }

func (m *AzureConditionalAccessPoliciesModule) Description() string {
	return "Enumerates Azure AD Conditional Access Policies via the Microsoft Graph API"
}

func (m *AzureConditionalAccessPoliciesModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies",
	}
}

func (m *AzureConditionalAccessPoliciesModule) SupportedResourceTypes() []string {
	return []string{"Microsoft.Graph/conditionalAccessPolicies"}
}

func (m *AzureConditionalAccessPoliciesModule) Parameters() any {
	return &m.AzureConditionalAccessPoliciesConfig
}

func (m *AzureConditionalAccessPoliciesModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(m.AzureCredential, nil)
	if err != nil {
		return fmt.Errorf("creating Graph client: %w", err)
	}

	policies, err := m.fetchPolicies(context.Background(), graphClient)
	if err != nil {
		return fmt.Errorf("fetching conditional access policies: %w", err)
	}

	slog.Info("collected conditional access policies", "count", len(policies))

	// Resolve UUIDs to human-readable names
	resolver := graphresolver.NewResolver(graphClient)
	collected := pipeline.From(policies...)
	resolved := pipeline.New[output.AzureConditionalAccessPolicy]()
	pipeline.Pipe(collected, resolver.Resolve, resolved)

	pipeline.Pipe(resolved, policyToModel, out)
	return out.Wait()
}

func policyToModel(p output.AzureConditionalAccessPolicy, out *pipeline.P[model.AurelianModel]) error {
	out.Send(p)
	return nil
}

func (m *AzureConditionalAccessPoliciesModule) fetchPolicies(ctx context.Context, client *msgraphsdk.GraphServiceClient) ([]output.AzureConditionalAccessPolicy, error) {
	result, err := client.Identity().ConditionalAccess().Policies().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("listing policies: %w", err)
	}
	if result == nil {
		return nil, nil
	}

	pageIterator, err := msgraphcore.NewPageIterator[models.ConditionalAccessPolicyable](
		result,
		client.GetAdapter(),
		models.CreateConditionalAccessPolicyCollectionResponseFromDiscriminatorValue,
	)
	if err != nil {
		return nil, fmt.Errorf("creating page iterator: %w", err)
	}

	var policies []output.AzureConditionalAccessPolicy
	err = pageIterator.Iterate(ctx, func(policy models.ConditionalAccessPolicyable) bool {
		if policy != nil {
			policies = append(policies, convertPolicy(policy))
		}
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("iterating policies: %w", err)
	}

	return policies, nil
}

func convertPolicy(p models.ConditionalAccessPolicyable) output.AzureConditionalAccessPolicy {
	result := output.AzureConditionalAccessPolicy{
		ID:          derefString(p.GetId()),
		DisplayName: derefString(p.GetDisplayName()),
		State:       convertPolicyState(p.GetState()),
		TemplateID:  derefString(p.GetTemplateId()),
	}

	if t := p.GetCreatedDateTime(); t != nil {
		result.CreatedDateTime = t.Format("2006-01-02T15:04:05Z")
	}
	if t := p.GetModifiedDateTime(); t != nil {
		result.ModifiedDateTime = t.Format("2006-01-02T15:04:05Z")
	}
	if c := p.GetConditions(); c != nil {
		result.Conditions = extractConditions(c)
	}
	if gc := p.GetGrantControls(); gc != nil {
		result.GrantControls = extractGrantControls(gc)
	}
	if sc := p.GetSessionControls(); sc != nil {
		result.SessionControls = extractSessionControls(sc)
	}

	return result
}

func extractConditions(c models.ConditionalAccessConditionSetable) *output.ConditionalAccessConditions {
	cond := &output.ConditionalAccessConditions{}

	if users := c.GetUsers(); users != nil {
		cond.Users = &output.ConditionalAccessUsers{
			IncludeUsers:  users.GetIncludeUsers(),
			ExcludeUsers:  users.GetExcludeUsers(),
			IncludeGroups: users.GetIncludeGroups(),
			ExcludeGroups: users.GetExcludeGroups(),
			IncludeRoles:  users.GetIncludeRoles(),
			ExcludeRoles:  users.GetExcludeRoles(),
		}
		if ig := users.GetIncludeGuestsOrExternalUsers(); ig != nil {
			cond.Users.IncludeGuestsOrExternalUsers = map[string]any{
				"guestOrExternalUserTypes": ig.GetGuestOrExternalUserTypes(),
				"externalTenants":          ig.GetExternalTenants(),
			}
		}
		if eg := users.GetExcludeGuestsOrExternalUsers(); eg != nil {
			cond.Users.ExcludeGuestsOrExternalUsers = map[string]any{
				"guestOrExternalUserTypes": eg.GetGuestOrExternalUserTypes(),
				"externalTenants":          eg.GetExternalTenants(),
			}
		}
	}

	if apps := c.GetApplications(); apps != nil {
		cond.Applications = &output.ConditionalAccessApplications{
			IncludeApplications: apps.GetIncludeApplications(),
			ExcludeApplications: apps.GetExcludeApplications(),
			IncludeUserActions:  apps.GetIncludeUserActions(),
		}
		if af := apps.GetApplicationFilter(); af != nil {
			cond.Applications.ApplicationFilter = map[string]any{
				"mode": convertFilterMode(af.GetMode()),
				"rule": derefString(af.GetRule()),
			}
		}
	}

	if loc := c.GetLocations(); loc != nil {
		cond.Locations = map[string]any{
			"includeLocations": loc.GetIncludeLocations(),
			"excludeLocations": loc.GetExcludeLocations(),
		}
	}

	if plat := c.GetPlatforms(); plat != nil {
		cond.Platforms = map[string]any{
			"includePlatforms": convertDevicePlatforms(plat.GetIncludePlatforms()),
			"excludePlatforms": convertDevicePlatforms(plat.GetExcludePlatforms()),
		}
	}

	cond.ClientAppTypes = convertClientAppTypes(c.GetClientAppTypes())
	cond.SignInRiskLevels = convertRiskLevels(c.GetSignInRiskLevels())
	cond.UserRiskLevels = convertRiskLevels(c.GetUserRiskLevels())

	return cond
}

func extractGrantControls(gc models.ConditionalAccessGrantControlsable) map[string]any {
	op := ""
	if gc.GetOperator() != nil {
		op = *gc.GetOperator()
	}
	return map[string]any{
		"operator":                    op,
		"builtInControls":             convertGrantControls(gc.GetBuiltInControls()),
		"customAuthenticationFactors": gc.GetCustomAuthenticationFactors(),
		"termsOfUse":                  gc.GetTermsOfUse(),
	}
}

func extractSessionControls(sc models.ConditionalAccessSessionControlsable) map[string]any {
	return map[string]any{
		"applicationEnforcedRestrictions": sc.GetApplicationEnforcedRestrictions(),
		"cloudAppSecurity":               sc.GetCloudAppSecurity(),
		"persistentBrowser":              sc.GetPersistentBrowser(),
		"signInFrequency":                sc.GetSignInFrequency(),
	}
}

func derefString(s *string) string {
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

func convertFilterMode(mode *models.FilterMode) string {
	if mode == nil {
		return ""
	}
	switch *mode {
	case models.INCLUDE_FILTERMODE:
		return "include"
	case models.EXCLUDE_FILTERMODE:
		return "exclude"
	default:
		return ""
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
		case models.EASSUPPORTED_CONDITIONALACCESSCLIENTAPP:
			result = append(result, "easSupported")
		case models.OTHER_CONDITIONALACCESSCLIENTAPP:
			result = append(result, "other")
		}
	}
	return result
}

func convertGrantControls(controls []models.ConditionalAccessGrantControl) []string {
	result := make([]string, 0, len(controls))
	for _, c := range controls {
		switch c {
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
		case models.UNKNOWNFUTUREVALUE_CONDITIONALACCESSGRANTCONTROL:
			result = append(result, "unknownFutureValue")
		}
	}
	return result
}

func convertDevicePlatforms(platforms []models.ConditionalAccessDevicePlatform) []string {
	result := make([]string, 0, len(platforms))
	for _, p := range platforms {
		switch p {
		case models.ANDROID_CONDITIONALACCESSDEVICEPLATFORM:
			result = append(result, "android")
		case models.IOS_CONDITIONALACCESSDEVICEPLATFORM:
			result = append(result, "iOS")
		case models.WINDOWS_CONDITIONALACCESSDEVICEPLATFORM:
			result = append(result, "windows")
		case models.WINDOWSPHONE_CONDITIONALACCESSDEVICEPLATFORM:
			result = append(result, "windowsPhone")
		case models.MACOS_CONDITIONALACCESSDEVICEPLATFORM:
			result = append(result, "macOS")
		case models.ALL_CONDITIONALACCESSDEVICEPLATFORM:
			result = append(result, "all")
		case models.UNKNOWNFUTUREVALUE_CONDITIONALACCESSDEVICEPLATFORM:
			result = append(result, "unknownFutureValue")
		case models.LINUX_CONDITIONALACCESSDEVICEPLATFORM:
			result = append(result, "linux")
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
		case models.HIDDEN_RISKLEVEL:
			result = append(result, "hidden")
		case models.NONE_RISKLEVEL:
			result = append(result, "none")
		case models.UNKNOWNFUTUREVALUE_RISKLEVEL:
			result = append(result, "unknownFutureValue")
		}
	}
	return result
}
