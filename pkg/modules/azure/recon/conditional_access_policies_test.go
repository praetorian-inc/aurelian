package recon

import (
	"testing"
	"time"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionalAccessPoliciesModuleMetadata(t *testing.T) {
	m := &AzureConditionalAccessPoliciesModule{}

	assert.Equal(t, "conditional-access-policies", m.ID())
	assert.Equal(t, "Azure Conditional Access Policies", m.Name())
	assert.Equal(t, plugin.PlatformAzure, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "safe", m.OpsecLevel())

	authors := m.Authors()
	require.Len(t, authors, 1)
	assert.Equal(t, "Praetorian", authors[0])

	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
	assert.Equal(t, []string{"Microsoft.Graph/conditionalAccessPolicies"}, m.SupportedResourceTypes())
}

func TestConditionalAccessPoliciesParameters(t *testing.T) {
	m := &AzureConditionalAccessPoliciesModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["output-dir"], "should have output-dir param")
	assert.False(t, paramNames["subscription-ids"], "Entra module should not expose subscription-ids")
}

func TestConvertPolicy_FullPolicy(t *testing.T) {
	policy := buildTestPolicy()

	result := convertPolicy(policy)

	assert.Equal(t, "policy-id-123", result.ID)
	assert.Equal(t, "Require MFA for admins", result.DisplayName)
	assert.Equal(t, "enabled", result.State)
	assert.Equal(t, "template-abc", result.TemplateID)
	assert.Equal(t, "2024-01-15T10:30:00Z", result.CreatedDateTime)
	assert.Equal(t, "2024-06-20T14:00:00Z", result.ModifiedDateTime)

	require.NotNil(t, result.Conditions)
	require.NotNil(t, result.Conditions.Users)
	assert.Equal(t, []string{"All"}, result.Conditions.Users.IncludeUsers)
	assert.Equal(t, []string{"guest-user-id"}, result.Conditions.Users.ExcludeUsers)
	assert.Equal(t, []string{"admins-group-id"}, result.Conditions.Users.IncludeGroups)
	assert.Equal(t, []string{"service-accounts-group-id"}, result.Conditions.Users.ExcludeGroups)
	assert.Equal(t, []string{"global-admin-role-id"}, result.Conditions.Users.IncludeRoles)
	assert.Equal(t, []string{"directory-readers-role-id"}, result.Conditions.Users.ExcludeRoles)

	require.NotNil(t, result.Conditions.Applications)
	assert.Equal(t, []string{"All"}, result.Conditions.Applications.IncludeApplications)
	assert.Equal(t, []string{"excluded-app-id"}, result.Conditions.Applications.ExcludeApplications)

	assert.Equal(t, []string{"browser", "mobileAppsAndDesktopClients"}, result.Conditions.ClientAppTypes)
	assert.Equal(t, []string{"high"}, result.Conditions.SignInRiskLevels)
	assert.Equal(t, []string{"medium"}, result.Conditions.UserRiskLevels)

	require.NotNil(t, result.GrantControls)
	assert.Equal(t, "OR", result.GrantControls["operator"])

	require.NotNil(t, result.SessionControls)
}

func TestConvertPolicy_MinimalPolicy(t *testing.T) {
	policy := models.NewConditionalAccessPolicy()
	id := "minimal-id"
	name := "Minimal Policy"
	policy.SetId(&id)
	policy.SetDisplayName(&name)

	result := convertPolicy(policy)

	assert.Equal(t, "minimal-id", result.ID)
	assert.Equal(t, "Minimal Policy", result.DisplayName)
	assert.Equal(t, "unknown", result.State)
	assert.Empty(t, result.TemplateID)
	assert.Empty(t, result.CreatedDateTime)
	assert.Empty(t, result.ModifiedDateTime)
	assert.Nil(t, result.Conditions)
	assert.Nil(t, result.GrantControls)
	assert.Nil(t, result.SessionControls)
}

func TestConvertPolicy_NilFields(t *testing.T) {
	policy := models.NewConditionalAccessPolicy()
	result := convertPolicy(policy)

	assert.Empty(t, result.ID)
	assert.Empty(t, result.DisplayName)
	assert.Equal(t, "unknown", result.State)
}

func TestConvertPolicyState(t *testing.T) {
	tests := []struct {
		name     string
		state    *models.ConditionalAccessPolicyState
		expected string
	}{
		{
			name:     "nil state",
			state:    nil,
			expected: "unknown",
		},
		{
			name:     "enabled",
			state:    ptr(models.ENABLED_CONDITIONALACCESSPOLICYSTATE),
			expected: "enabled",
		},
		{
			name:     "disabled",
			state:    ptr(models.DISABLED_CONDITIONALACCESSPOLICYSTATE),
			expected: "disabled",
		},
		{
			name:     "report only",
			state:    ptr(models.ENABLEDFORREPORTINGBUTNOTENFORCED_CONDITIONALACCESSPOLICYSTATE),
			expected: "enabledForReportingButNotEnforced",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, convertPolicyState(tt.state))
		})
	}
}

func TestConvertFilterMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     *models.FilterMode
		expected string
	}{
		{"nil", nil, ""},
		{"include", ptr(models.INCLUDE_FILTERMODE), "include"},
		{"exclude", ptr(models.EXCLUDE_FILTERMODE), "exclude"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, convertFilterMode(tt.mode))
		})
	}
}

func TestConvertClientAppTypes(t *testing.T) {
	t.Run("all client app types", func(t *testing.T) {
		apps := []models.ConditionalAccessClientApp{
			models.ALL_CONDITIONALACCESSCLIENTAPP,
			models.BROWSER_CONDITIONALACCESSCLIENTAPP,
			models.MOBILEAPPSANDDESKTOPCLIENTS_CONDITIONALACCESSCLIENTAPP,
			models.EXCHANGEACTIVESYNC_CONDITIONALACCESSCLIENTAPP,
			models.EASSUPPORTED_CONDITIONALACCESSCLIENTAPP,
			models.OTHER_CONDITIONALACCESSCLIENTAPP,
		}
		result := convertClientAppTypes(apps)
		assert.Equal(t, []string{
			"all", "browser", "mobileAppsAndDesktopClients",
			"exchangeActiveSync", "easSupported", "other",
		}, result)
	})

	t.Run("empty input", func(t *testing.T) {
		result := convertClientAppTypes(nil)
		assert.Empty(t, result)
	})

	t.Run("single type", func(t *testing.T) {
		result := convertClientAppTypes([]models.ConditionalAccessClientApp{
			models.BROWSER_CONDITIONALACCESSCLIENTAPP,
		})
		assert.Equal(t, []string{"browser"}, result)
	})
}

func TestConvertRiskLevels(t *testing.T) {
	t.Run("all risk levels", func(t *testing.T) {
		risks := []models.RiskLevel{
			models.LOW_RISKLEVEL,
			models.MEDIUM_RISKLEVEL,
			models.HIGH_RISKLEVEL,
			models.HIDDEN_RISKLEVEL,
			models.NONE_RISKLEVEL,
			models.UNKNOWNFUTUREVALUE_RISKLEVEL,
		}
		result := convertRiskLevels(risks)
		assert.Equal(t, []string{
			"low", "medium", "high", "hidden", "none", "unknownFutureValue",
		}, result)
	})

	t.Run("empty input", func(t *testing.T) {
		result := convertRiskLevels(nil)
		assert.Empty(t, result)
	})

	t.Run("single risk level", func(t *testing.T) {
		result := convertRiskLevels([]models.RiskLevel{models.HIGH_RISKLEVEL})
		assert.Equal(t, []string{"high"}, result)
	})
}

func TestExtractConditions_WithLocationsAndPlatforms(t *testing.T) {
	cond := models.NewConditionalAccessConditionSet()

	locations := models.NewConditionalAccessLocations()
	locations.SetIncludeLocations([]string{"AllTrusted"})
	locations.SetExcludeLocations([]string{"named-location-id"})
	cond.SetLocations(locations)

	platforms := models.NewConditionalAccessPlatforms()
	platforms.SetIncludePlatforms([]models.ConditionalAccessDevicePlatform{
		models.ANDROID_CONDITIONALACCESSDEVICEPLATFORM,
		models.IOS_CONDITIONALACCESSDEVICEPLATFORM,
	})
	platforms.SetExcludePlatforms([]models.ConditionalAccessDevicePlatform{
		models.WINDOWS_CONDITIONALACCESSDEVICEPLATFORM,
	})
	cond.SetPlatforms(platforms)

	result := extractConditions(cond)

	require.NotNil(t, result.Locations)
	assert.Equal(t, []string{"AllTrusted"}, result.Locations["includeLocations"])
	assert.Equal(t, []string{"named-location-id"}, result.Locations["excludeLocations"])

	require.NotNil(t, result.Platforms)
	assert.NotNil(t, result.Platforms["includePlatforms"])
	assert.NotNil(t, result.Platforms["excludePlatforms"])
}

func TestExtractConditions_EmptyConditions(t *testing.T) {
	cond := models.NewConditionalAccessConditionSet()
	result := extractConditions(cond)

	assert.Nil(t, result.Users)
	assert.Nil(t, result.Applications)
	assert.Nil(t, result.Locations)
	assert.Nil(t, result.Platforms)
	assert.Empty(t, result.ClientAppTypes)
	assert.Empty(t, result.SignInRiskLevels)
	assert.Empty(t, result.UserRiskLevels)
}

func TestExtractGrantControls_WithBuiltInControls(t *testing.T) {
	gc := models.NewConditionalAccessGrantControls()
	op := "AND"
	gc.SetOperator(&op)
	gc.SetBuiltInControls([]models.ConditionalAccessGrantControl{
		models.MFA_CONDITIONALACCESSGRANTCONTROL,
		models.COMPLIANTDEVICE_CONDITIONALACCESSGRANTCONTROL,
	})
	gc.SetTermsOfUse([]string{"tou-id-1"})

	result := extractGrantControls(gc)

	assert.Equal(t, "AND", result["operator"])
	controls := result["builtInControls"].([]string)
	assert.Equal(t, []string{"mfa", "compliantDevice"}, controls)
	assert.Equal(t, []string{"tou-id-1"}, result["termsOfUse"])
}

func TestExtractGrantControls_NilOperator(t *testing.T) {
	gc := models.NewConditionalAccessGrantControls()
	result := extractGrantControls(gc)
	assert.Equal(t, "", result["operator"])
}

func TestExtractSessionControls(t *testing.T) {
	sc := models.NewConditionalAccessSessionControls()

	freq := models.NewSignInFrequencySessionControl()
	sc.SetSignInFrequency(freq)

	browser := models.NewPersistentBrowserSessionControl()
	sc.SetPersistentBrowser(browser)

	result := extractSessionControls(sc)

	assert.NotNil(t, result["signInFrequency"])
	assert.NotNil(t, result["persistentBrowser"])
}

func TestDerefString(t *testing.T) {
	t.Run("non-nil", func(t *testing.T) {
		s := "hello"
		assert.Equal(t, "hello", derefString(&s))
	})

	t.Run("nil", func(t *testing.T) {
		assert.Equal(t, "", derefString(nil))
	})
}

func TestPolicyToModel(t *testing.T) {
	policy := output.AzureConditionalAccessPolicy{
		ID:          "test-id",
		DisplayName: "Test Policy",
		State:       "enabled",
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		require.NoError(t, policyToModel(policy, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	result, ok := items[0].(output.AzureConditionalAccessPolicy)
	require.True(t, ok)
	assert.Equal(t, "test-id", result.ID)
	assert.Equal(t, "Test Policy", result.DisplayName)
	assert.Equal(t, "enabled", result.State)
}

func TestConvertPolicy_ApplicationFilterWithMode(t *testing.T) {
	policy := models.NewConditionalAccessPolicy()
	id := "app-filter-policy"
	policy.SetId(&id)
	state := models.ENABLED_CONDITIONALACCESSPOLICYSTATE
	policy.SetState(&state)

	cond := models.NewConditionalAccessConditionSet()
	apps := models.NewConditionalAccessApplications()
	apps.SetIncludeApplications([]string{"All"})

	filter := models.NewConditionalAccessFilter()
	mode := models.INCLUDE_FILTERMODE
	filter.SetMode(&mode)
	rule := "CustomSecurityAttribute.MyAttr -eq 'value'"
	filter.SetRule(&rule)
	apps.SetApplicationFilter(filter)

	cond.SetApplications(apps)
	policy.SetConditions(cond)

	result := convertPolicy(policy)

	require.NotNil(t, result.Conditions.Applications.ApplicationFilter)
	assert.Equal(t, "include", result.Conditions.Applications.ApplicationFilter["mode"])
	assert.Equal(t, "CustomSecurityAttribute.MyAttr -eq 'value'", result.Conditions.Applications.ApplicationFilter["rule"])
}

func TestConvertPolicy_GuestsOrExternalUsers(t *testing.T) {
	policy := models.NewConditionalAccessPolicy()
	id := "guest-policy"
	policy.SetId(&id)

	cond := models.NewConditionalAccessConditionSet()
	users := models.NewConditionalAccessUsers()
	users.SetIncludeUsers([]string{"GuestsOrExternalUsers"})

	guestConfig := models.NewConditionalAccessGuestsOrExternalUsers()
	guestType := models.ConditionalAccessGuestOrExternalUserTypes(models.INTERNALGUEST_CONDITIONALACCESSGUESTOREXTERNALUSERTYPES)
	guestConfig.SetGuestOrExternalUserTypes(&guestType)
	users.SetIncludeGuestsOrExternalUsers(guestConfig)

	cond.SetUsers(users)
	policy.SetConditions(cond)

	result := convertPolicy(policy)

	require.NotNil(t, result.Conditions.Users.IncludeGuestsOrExternalUsers)
	assert.NotNil(t, result.Conditions.Users.IncludeGuestsOrExternalUsers["guestOrExternalUserTypes"])
	assert.Nil(t, result.Conditions.Users.ExcludeGuestsOrExternalUsers)
}

// buildTestPolicy constructs a fully-populated ConditionalAccessPolicy for testing.
func buildTestPolicy() models.ConditionalAccessPolicyable {
	policy := models.NewConditionalAccessPolicy()

	id := "policy-id-123"
	policy.SetId(&id)
	name := "Require MFA for admins"
	policy.SetDisplayName(&name)
	state := models.ENABLED_CONDITIONALACCESSPOLICYSTATE
	policy.SetState(&state)
	templateID := "template-abc"
	policy.SetTemplateId(&templateID)

	created := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	policy.SetCreatedDateTime(&created)
	modified := time.Date(2024, 6, 20, 14, 0, 0, 0, time.UTC)
	policy.SetModifiedDateTime(&modified)

	// Conditions
	cond := models.NewConditionalAccessConditionSet()

	users := models.NewConditionalAccessUsers()
	users.SetIncludeUsers([]string{"All"})
	users.SetExcludeUsers([]string{"guest-user-id"})
	users.SetIncludeGroups([]string{"admins-group-id"})
	users.SetExcludeGroups([]string{"service-accounts-group-id"})
	users.SetIncludeRoles([]string{"global-admin-role-id"})
	users.SetExcludeRoles([]string{"directory-readers-role-id"})
	cond.SetUsers(users)

	apps := models.NewConditionalAccessApplications()
	apps.SetIncludeApplications([]string{"All"})
	apps.SetExcludeApplications([]string{"excluded-app-id"})
	cond.SetApplications(apps)

	cond.SetClientAppTypes([]models.ConditionalAccessClientApp{
		models.BROWSER_CONDITIONALACCESSCLIENTAPP,
		models.MOBILEAPPSANDDESKTOPCLIENTS_CONDITIONALACCESSCLIENTAPP,
	})
	cond.SetSignInRiskLevels([]models.RiskLevel{models.HIGH_RISKLEVEL})
	cond.SetUserRiskLevels([]models.RiskLevel{models.MEDIUM_RISKLEVEL})

	policy.SetConditions(cond)

	// Grant controls
	gc := models.NewConditionalAccessGrantControls()
	op := "OR"
	gc.SetOperator(&op)
	gc.SetBuiltInControls([]models.ConditionalAccessGrantControl{
		models.MFA_CONDITIONALACCESSGRANTCONTROL,
	})
	policy.SetGrantControls(gc)

	// Session controls
	sc := models.NewConditionalAccessSessionControls()
	freq := models.NewSignInFrequencySessionControl()
	sc.SetSignInFrequency(freq)
	policy.SetSessionControls(sc)

	return policy
}

func ptr[T any](v T) *T { return &v }
