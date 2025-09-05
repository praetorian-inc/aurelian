package azure

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
)

type AzureConditionalAccessCollectorLink struct {
	*chain.Base
}

func NewAzureConditionalAccessCollectorLink(configs ...cfg.Config) chain.Link {
	l := &AzureConditionalAccessCollectorLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureConditionalAccessCollectorLink) Params() []cfg.Param {
	return []cfg.Param{}
}

type ConditionalAccessPolicyResult struct {
	ID               string                                 `json:"id"`
	DisplayName      string                                 `json:"displayName"`
	State            string                                 `json:"state"`
	TemplateID       *string                               `json:"templateId,omitempty"`
	CreatedDateTime  string                                 `json:"createdDateTime"`
	ModifiedDateTime string                                 `json:"modifiedDateTime"`
	Conditions       *ConditionalAccessConditionSet         `json:"conditions,omitempty"`
	GrantControls    map[string]interface{}                 `json:"grantControls,omitempty"`
	SessionControls  map[string]interface{}                 `json:"sessionControls,omitempty"`
}

type ConditionalAccessConditionSet struct {
	Users              *ConditionalAccessUsers        `json:"users,omitempty"`
	Applications       *ConditionalAccessApplications `json:"applications,omitempty"`
	Locations          map[string]interface{}         `json:"locations,omitempty"`
	Platforms          map[string]interface{}         `json:"platforms,omitempty"`
	ClientAppTypes     []string                       `json:"clientAppTypes,omitempty"`
	SignInRiskLevels   []string                       `json:"signInRiskLevels,omitempty"`
	UserRiskLevels     []string                       `json:"userRiskLevels,omitempty"`
	DeviceStates       map[string]interface{}         `json:"deviceStates,omitempty"`
}

type ConditionalAccessUsers struct {
	IncludeUsers                    []string                       `json:"includeUsers,omitempty"`
	ExcludeUsers                    []string                       `json:"excludeUsers,omitempty"`
	IncludeGroups                   []string                       `json:"includeGroups,omitempty"`
	ExcludeGroups                   []string                       `json:"excludeGroups,omitempty"`
	IncludeRoles                    []string                       `json:"includeRoles,omitempty"`
	ExcludeRoles                    []string                       `json:"excludeRoles,omitempty"`
	IncludeGuestsOrExternalUsers    map[string]interface{}         `json:"includeGuestsOrExternalUsers,omitempty"`
	ExcludeGuestsOrExternalUsers    map[string]interface{}         `json:"excludeGuestsOrExternalUsers,omitempty"`
}

type ConditionalAccessApplications struct {
	IncludeApplications []string                       `json:"includeApplications,omitempty"`
	ExcludeApplications []string                       `json:"excludeApplications,omitempty"`
	IncludeUserActions  []string                       `json:"includeUserActions,omitempty"`
	ApplicationFilter   map[string]interface{}         `json:"applicationFilter,omitempty"`
}

func (l *AzureConditionalAccessCollectorLink) Process(input any) error {
	slog.Info("Starting Azure Conditional Access Policy collection")

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create Graph client
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Graph client: %w", err)
	}

	// Retrieve all conditional access policies
	policies, err := l.getConditionalAccessPolicies(l.Context(), graphClient)
	if err != nil {
		return fmt.Errorf("failed to retrieve conditional access policies: %w", err)
	}

	slog.Info("Successfully collected conditional access policies", "count", len(policies))

	// Pass the raw policy data to the next link for UUID resolution
	return l.Send(policies)
}

func (l *AzureConditionalAccessCollectorLink) getConditionalAccessPolicies(ctx context.Context, graphClient *msgraphsdk.GraphServiceClient) ([]ConditionalAccessPolicyResult, error) {
	var allPolicies []ConditionalAccessPolicyResult

	// Get first page of conditional access policies from Microsoft Graph
	result, err := graphClient.Identity().ConditionalAccess().Policies().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get conditional access policies: %w", err)
	}

	if result == nil {
		slog.Info("No conditional access policies found")
		return allPolicies, nil
	}

	// Create PageIterator to handle pagination across all pages
	pageIterator, err := msgraphcore.NewPageIterator[models.ConditionalAccessPolicyable](
		result,
		graphClient.GetAdapter(),
		models.CreateConditionalAccessPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, fmt.Errorf("failed to create page iterator: %w", err)
	}

	// Iterate through all pages and convert each policy
	err = pageIterator.Iterate(ctx, func(policy models.ConditionalAccessPolicyable) bool {
		if policy != nil {
			policyResult := l.convertPolicyToResult(policy)
			allPolicies = append(allPolicies, policyResult)
		}
		return true // continue iteration
	})

	if err != nil {
		return nil, fmt.Errorf("failed to iterate through conditional access policies: %w", err)
	}

	return allPolicies, nil
}

func (l *AzureConditionalAccessCollectorLink) convertPolicyToResult(policy models.ConditionalAccessPolicyable) ConditionalAccessPolicyResult {
	policyResult := ConditionalAccessPolicyResult{
		ID:          safeStringDeref(policy.GetId()),
		DisplayName: safeStringDeref(policy.GetDisplayName()),
		State:       l.convertPolicyState(policy.GetState()),
	}

	// Handle optional fields
	if policy.GetTemplateId() != nil {
		templateID := *policy.GetTemplateId()
		policyResult.TemplateID = &templateID
	}

	if policy.GetCreatedDateTime() != nil {
		policyResult.CreatedDateTime = policy.GetCreatedDateTime().Format("2006-01-02T15:04:05Z")
	}

	if policy.GetModifiedDateTime() != nil {
		policyResult.ModifiedDateTime = policy.GetModifiedDateTime().Format("2006-01-02T15:04:05Z")
	}

	// Extract conditions
	if conditions := policy.GetConditions(); conditions != nil {
		policyResult.Conditions = l.extractConditions(conditions)
	}

	// Extract grant controls (raw for now, will be processed later)
	if grantControls := policy.GetGrantControls(); grantControls != nil {
		op := ""
		if grantControls.GetOperator() != nil {
			op = *grantControls.GetOperator()
		}
		policyResult.GrantControls = map[string]interface{}{
			"operator":                    op,
			"builtInControls":             grantControls.GetBuiltInControls(),
			"customAuthenticationFactors": grantControls.GetCustomAuthenticationFactors(),
			"termsOfUse":                  grantControls.GetTermsOfUse(),
		}
	}

	// Extract session controls (raw for now, will be processed later)
	if sessionControls := policy.GetSessionControls(); sessionControls != nil {
		policyResult.SessionControls = map[string]interface{}{
			"applicationEnforcedRestrictions": sessionControls.GetApplicationEnforcedRestrictions(),
			"cloudAppSecurity":               sessionControls.GetCloudAppSecurity(),
			"persistentBrowser":              sessionControls.GetPersistentBrowser(),
			"signInFrequency":               sessionControls.GetSignInFrequency(),
		}
	}

	return policyResult
}

func (l *AzureConditionalAccessCollectorLink) extractConditions(conditions models.ConditionalAccessConditionSetable) *ConditionalAccessConditionSet {
	result := &ConditionalAccessConditionSet{}

	// Extract users
	if users := conditions.GetUsers(); users != nil {
		result.Users = &ConditionalAccessUsers{
			IncludeUsers:  users.GetIncludeUsers(),
			ExcludeUsers:  users.GetExcludeUsers(),
			IncludeGroups: users.GetIncludeGroups(),
			ExcludeGroups: users.GetExcludeGroups(),
			IncludeRoles:  users.GetIncludeRoles(),
			ExcludeRoles:  users.GetExcludeRoles(),
		}

		// Handle guest/external users (complex object, store as raw for now)
		if includeGuests := users.GetIncludeGuestsOrExternalUsers(); includeGuests != nil {
			result.Users.IncludeGuestsOrExternalUsers = map[string]interface{}{
				"guestOrExternalUserTypes": includeGuests.GetGuestOrExternalUserTypes(),
				"externalTenants":         includeGuests.GetExternalTenants(),
			}
		}

		if excludeGuests := users.GetExcludeGuestsOrExternalUsers(); excludeGuests != nil {
			result.Users.ExcludeGuestsOrExternalUsers = map[string]interface{}{
				"guestOrExternalUserTypes": excludeGuests.GetGuestOrExternalUserTypes(),
				"externalTenants":         excludeGuests.GetExternalTenants(),
			}
		}
	}

	// Extract applications
	if apps := conditions.GetApplications(); apps != nil {
		result.Applications = &ConditionalAccessApplications{
			IncludeApplications: apps.GetIncludeApplications(),
			ExcludeApplications: apps.GetExcludeApplications(),
			IncludeUserActions:  apps.GetIncludeUserActions(),
		}

		if appFilter := apps.GetApplicationFilter(); appFilter != nil {
			result.Applications.ApplicationFilter = map[string]interface{}{
				"mode": l.convertFilterMode(appFilter.GetMode()),
				"rule": safeStringDeref(appFilter.GetRule()),
			}
		}
	}

	// Extract other conditions as raw data (locations, platforms, etc.)
	if locations := conditions.GetLocations(); locations != nil {
		result.Locations = map[string]interface{}{
			"includeLocations": locations.GetIncludeLocations(),
			"excludeLocations": locations.GetExcludeLocations(),
		}
	}

	if platforms := conditions.GetPlatforms(); platforms != nil {
		result.Platforms = map[string]interface{}{
			"includePlatforms": platforms.GetIncludePlatforms(),
			"excludePlatforms": platforms.GetExcludePlatforms(),
		}
	}

	// Extract risk levels and client app types
	result.ClientAppTypes = l.convertClientAppTypes(conditions.GetClientAppTypes())
	result.SignInRiskLevels = l.convertRiskLevels(conditions.GetSignInRiskLevels())
	result.UserRiskLevels = l.convertRiskLevels(conditions.GetUserRiskLevels())

	// Note: DeviceStates may not be available in all API versions
	// Commenting out for now to avoid compilation errors
	// if deviceStates := conditions.GetDeviceStates(); deviceStates != nil {
	// 	result.DeviceStates = map[string]interface{}{
	// 		"includeStates": deviceStates.GetIncludeStates(),
	// 		"excludeStates": deviceStates.GetExcludeStates(),
	// 	}
	// }

	return result
}

// Helper function to safely dereference string pointers
func safeStringDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Helper function to convert policy state enum to string
func (l *AzureConditionalAccessCollectorLink) convertPolicyState(state *models.ConditionalAccessPolicyState) string {
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

// Helper function to convert FilterMode enum to string
func (l *AzureConditionalAccessCollectorLink) convertFilterMode(mode *models.FilterMode) string {
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

// Helper function to convert client app types enum array to string array
func (l *AzureConditionalAccessCollectorLink) convertClientAppTypes(clientApps []models.ConditionalAccessClientApp) []string {
	var result []string
	for _, app := range clientApps {
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

// Helper function to convert risk levels enum array to string array
func (l *AzureConditionalAccessCollectorLink) convertRiskLevels(risks []models.RiskLevel) []string {
	var result []string
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