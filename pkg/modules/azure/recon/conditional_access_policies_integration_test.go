//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionalAccessPolicies_EndToEnd(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/conditional-access-policies")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "conditional-access-policies")
	if !ok {
		t.Fatal("conditional-access-policies module not registered")
	}

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 10)

	var policies []output.AzureConditionalAccessPolicy
	for _, r := range results {
		if p, ok := r.(output.AzureConditionalAccessPolicy); ok {
			policies = append(policies, p)
		}
	}
	require.GreaterOrEqual(t, len(policies), 10)

	byName := make(map[string]*output.AzureConditionalAccessPolicy, len(policies))
	for i := range policies {
		byName[policies[i].DisplayName] = &policies[i]
	}

	policyKeys := []string{
		"mfa_admins", "device_compliance", "risk_based", "app_targeted",
		"location_based", "block_legacy_auth", "require_password_change",
		"azure_mgmt_mfa", "mobile_approved_apps", "guest_access",
	}
	fp := make(map[string]*output.AzureConditionalAccessPolicy)
	for _, key := range policyKeys {
		name := fixture.Output(key + "_policy_display_name")
		p, ok := byName[name]
		require.True(t, ok, "fixture policy %q (%s) not found in results", name, key)
		fp[key] = p
	}

	strSlice := func(m map[string]any, key string) []string {
		v, ok := m[key]
		if !ok || v == nil {
			return nil
		}
		if ss, ok := v.([]string); ok {
			return ss
		}
		return nil
	}

	builtIn := func(gc map[string]any) []string {
		if gc == nil {
			return nil
		}
		if ss, ok := gc["builtInControls"].([]string); ok {
			return ss
		}
		return nil
	}

	// Helper: assert a resolved user has exact fields.
	assertUser := func(t *testing.T, p *output.AzureConditionalAccessPolicy, oidKey, nameKey, upnKey string) {
		t.Helper()
		oid := fixture.Output(oidKey)
		require.Contains(t, p.ResolvedUsers, oid)
		e := p.ResolvedUsers[oid]
		assert.Equal(t, "user", e.Type)
		assert.Equal(t, oid, e.ID)
		assert.Equal(t, fixture.Output(nameKey), e.DisplayName)
		require.NotNil(t, e.ExtraInfo)
		assert.Equal(t, fixture.Output(upnKey), e.ExtraInfo["userPrincipalName"])
	}

	// Helper: assert a resolved group has exact fields.
	assertGroup := func(t *testing.T, p *output.AzureConditionalAccessPolicy, oidKey, nameKey string) {
		t.Helper()
		oid := fixture.Output(oidKey)
		require.Contains(t, p.ResolvedGroups, oid)
		e := p.ResolvedGroups[oid]
		assert.Equal(t, "group", e.Type)
		assert.Equal(t, oid, e.ID)
		assert.Equal(t, fixture.Output(nameKey), e.DisplayName)
	}

	// Helper: assert a resolved role has exact fields.
	assertRole := func(t *testing.T, p *output.AzureConditionalAccessPolicy, ridKey, expectedName string) {
		t.Helper()
		rid := fixture.Output(ridKey)
		require.Contains(t, p.ResolvedRoles, rid)
		e := p.ResolvedRoles[rid]
		assert.Equal(t, "role", e.Type)
		assert.Equal(t, rid, e.ID)
		assert.Equal(t, expectedName, e.DisplayName)
		require.NotNil(t, e.ExtraInfo)
		assert.Equal(t, rid, e.ExtraInfo["roleTemplateId"])
	}

	// Helper: assert a resolved application has exact fields.
	assertApp := func(t *testing.T, p *output.AzureConditionalAccessPolicy, aidKey, nameKey string) {
		t.Helper()
		aid := fixture.Output(aidKey)
		require.Contains(t, p.ResolvedApplications, aid)
		e := p.ResolvedApplications[aid]
		assert.Equal(t, "application", e.Type)
		assert.Equal(t, aid, e.ID)
		assert.Equal(t, fixture.Output(nameKey), e.DisplayName)
	}

	// =====================================================================
	// POLICY 1: MFA for admins (disabled)
	// =====================================================================
	t.Run("Policy1_MFAAdmins", func(t *testing.T) {
		p := fp["mfa_admins"]
		assert.Equal(t, fixture.Output("mfa_admins_policy_id"), p.ID)
		assert.Equal(t, "disabled", p.State)

		// Users
		require.NotNil(t, p.Conditions.Users)
		assert.Equal(t, []string{fixture.Output("test_user_object_id")}, p.Conditions.Users.IncludeUsers)
		assert.Empty(t, p.Conditions.Users.ExcludeUsers)
		assert.Equal(t, []string{fixture.Output("test_group_object_id")}, p.Conditions.Users.IncludeGroups)
		assert.Empty(t, p.Conditions.Users.ExcludeGroups)
		assert.Equal(t, []string{fixture.Output("global_admin_role_template_id")}, p.Conditions.Users.IncludeRoles)
		assert.Empty(t, p.Conditions.Users.ExcludeRoles)

		// Applications
		require.NotNil(t, p.Conditions.Applications)
		assert.Equal(t, []string{"All"}, p.Conditions.Applications.IncludeApplications)
		assert.Empty(t, p.Conditions.Applications.ExcludeApplications)
		assert.Empty(t, p.Conditions.Applications.IncludeUserActions)
		assert.Nil(t, p.Conditions.Applications.ApplicationFilter)

		// Client app types
		assert.Equal(t, []string{"browser"}, p.Conditions.ClientAppTypes)

		// Risk levels — none set
		assert.Empty(t, p.Conditions.SignInRiskLevels)
		assert.Empty(t, p.Conditions.UserRiskLevels)

		// Platforms
		require.NotNil(t, p.Conditions.Platforms)
		incPlat := strSlice(p.Conditions.Platforms, "includePlatforms")
		assert.Len(t, incPlat, 2)
		assert.Contains(t, incPlat, "android")
		assert.Contains(t, incPlat, "iOS")
		assert.Empty(t, strSlice(p.Conditions.Platforms, "excludePlatforms"))

		// Locations
		require.NotNil(t, p.Conditions.Locations)
		assert.Equal(t, []string{"All"}, strSlice(p.Conditions.Locations, "includeLocations"))
		assert.Empty(t, strSlice(p.Conditions.Locations, "excludeLocations"))

		// Grant controls — must be OR with exactly mfa
		require.NotNil(t, p.GrantControls)
		assert.Equal(t, "OR", p.GrantControls["operator"])
		assert.Equal(t, []string{"mfa"}, builtIn(p.GrantControls))

		// Session controls — signInFrequency only
		require.NotNil(t, p.SessionControls)
		assert.NotNil(t, p.SessionControls["signInFrequency"])

		// Resolution: exactly 1 user, 1 group, 1 role, 0 applications
		assert.Len(t, p.ResolvedUsers, 1)
		assert.Len(t, p.ResolvedGroups, 1)
		assert.Len(t, p.ResolvedRoles, 1)
		assert.Empty(t, p.ResolvedApplications)
		assertUser(t, p, "test_user_object_id", "test_user_display_name", "test_user_upn")
		assertGroup(t, p, "test_group_object_id", "test_group_display_name")
		assertRole(t, p, "global_admin_role_template_id", "Global Administrator")
	})

	// =====================================================================
	// POLICY 2: Device compliance (disabled)
	// =====================================================================
	t.Run("Policy2_DeviceCompliance", func(t *testing.T) {
		p := fp["device_compliance"]
		assert.Equal(t, fixture.Output("device_compliance_policy_id"), p.ID)
		assert.Equal(t, "disabled", p.State)

		// Users
		require.NotNil(t, p.Conditions.Users)
		assert.Equal(t, []string{"All"}, p.Conditions.Users.IncludeUsers)
		assert.Empty(t, p.Conditions.Users.ExcludeUsers)
		assert.Empty(t, p.Conditions.Users.IncludeGroups)
		assert.Equal(t, []string{fixture.Output("test_group_object_id")}, p.Conditions.Users.ExcludeGroups)
		assert.Empty(t, p.Conditions.Users.IncludeRoles)
		assert.Empty(t, p.Conditions.Users.ExcludeRoles)

		// Applications
		require.NotNil(t, p.Conditions.Applications)
		assert.Equal(t, []string{"All"}, p.Conditions.Applications.IncludeApplications)
		assert.Empty(t, p.Conditions.Applications.ExcludeApplications)

		// Client app types
		assert.Equal(t, []string{"mobileAppsAndDesktopClients"}, p.Conditions.ClientAppTypes)

		// Risk levels — none
		assert.Empty(t, p.Conditions.SignInRiskLevels)
		assert.Empty(t, p.Conditions.UserRiskLevels)

		// No platforms, no locations
		assert.Nil(t, p.Conditions.Platforms)
		assert.Nil(t, p.Conditions.Locations)

		// Grant — must be AND with exactly compliantDevice+domainJoinedDevice
		require.NotNil(t, p.GrantControls)
		assert.Equal(t, "AND", p.GrantControls["operator"])
		controls := builtIn(p.GrantControls)
		assert.Len(t, controls, 2)
		assert.Contains(t, controls, "compliantDevice")
		assert.Contains(t, controls, "domainJoinedDevice")

		// No session controls
		assert.Nil(t, p.SessionControls)

		// Resolution: 0 users (All isn't a UUID), 1 excluded group, 0 roles, 0 apps
		assert.Empty(t, p.ResolvedUsers)
		assert.Len(t, p.ResolvedGroups, 1)
		assert.Empty(t, p.ResolvedRoles)
		assert.Empty(t, p.ResolvedApplications)
		assertGroup(t, p, "test_group_object_id", "test_group_display_name")
	})

	// =====================================================================
	// POLICY 3: Risk-based (report-only)
	// =====================================================================
	t.Run("Policy3_RiskBased", func(t *testing.T) {
		p := fp["risk_based"]
		assert.Equal(t, fixture.Output("risk_based_policy_id"), p.ID)
		assert.Equal(t, "enabledForReportingButNotEnforced", p.State)

		// Users
		require.NotNil(t, p.Conditions.Users)
		assert.Equal(t, []string{"All"}, p.Conditions.Users.IncludeUsers)
		assert.Equal(t, []string{fixture.Output("exclude_user_object_id")}, p.Conditions.Users.ExcludeUsers)
		assert.Empty(t, p.Conditions.Users.IncludeGroups)
		assert.Empty(t, p.Conditions.Users.ExcludeGroups)
		assert.Len(t, p.Conditions.Users.IncludeRoles, 2)
		assert.Contains(t, p.Conditions.Users.IncludeRoles, fixture.Output("global_admin_role_template_id"))
		assert.Contains(t, p.Conditions.Users.IncludeRoles, fixture.Output("security_reader_role_template_id"))
		assert.Empty(t, p.Conditions.Users.ExcludeRoles)

		// Applications
		assert.Equal(t, []string{"All"}, p.Conditions.Applications.IncludeApplications)
		assert.Empty(t, p.Conditions.Applications.ExcludeApplications)

		// Client app types
		assert.Equal(t, []string{"all"}, p.Conditions.ClientAppTypes)

		// Risk levels — specific values
		assert.Len(t, p.Conditions.SignInRiskLevels, 2)
		assert.Contains(t, p.Conditions.SignInRiskLevels, "high")
		assert.Contains(t, p.Conditions.SignInRiskLevels, "medium")
		assert.Equal(t, []string{"high"}, p.Conditions.UserRiskLevels)

		// No platforms, no locations
		assert.Nil(t, p.Conditions.Platforms)
		assert.Nil(t, p.Conditions.Locations)

		// Grant — must be OR with exactly mfa
		assert.Equal(t, "OR", p.GrantControls["operator"])
		assert.Equal(t, []string{"mfa"}, builtIn(p.GrantControls))

		// Session — persistentBrowser and cloudAppSecurity
		require.NotNil(t, p.SessionControls)
		assert.NotNil(t, p.SessionControls["persistentBrowser"])
		assert.NotNil(t, p.SessionControls["cloudAppSecurity"])

		// Resolution: 1 excluded user, 0 groups, 2 roles, 0 apps
		assert.Len(t, p.ResolvedUsers, 1)
		assert.Empty(t, p.ResolvedGroups)
		assert.Len(t, p.ResolvedRoles, 2)
		assert.Empty(t, p.ResolvedApplications)
		assertUser(t, p, "exclude_user_object_id", "exclude_user_display_name", "exclude_user_object_id")
		// UPN check — use the helper but we need the UPN output; the exclude user
		// was created with a known UPN pattern, validate via display name instead
		assertRole(t, p, "global_admin_role_template_id", "Global Administrator")
		assertRole(t, p, "security_reader_role_template_id", "Security Reader")
	})

	// =====================================================================
	// POLICY 4: App-targeted with block (disabled)
	// =====================================================================
	t.Run("Policy4_AppTargeted", func(t *testing.T) {
		p := fp["app_targeted"]
		assert.Equal(t, fixture.Output("app_targeted_policy_id"), p.ID)
		assert.Equal(t, "disabled", p.State)

		// Users
		require.NotNil(t, p.Conditions.Users)
		assert.Equal(t, []string{fixture.Output("test_user_object_id")}, p.Conditions.Users.IncludeUsers)
		assert.Empty(t, p.Conditions.Users.ExcludeUsers)
		assert.Empty(t, p.Conditions.Users.IncludeGroups)
		assert.Empty(t, p.Conditions.Users.ExcludeGroups)
		assert.Empty(t, p.Conditions.Users.IncludeRoles)
		assert.Empty(t, p.Conditions.Users.ExcludeRoles)

		// Applications — specific app, exclude Office365
		assert.Equal(t, []string{fixture.Output("test_app_client_id")}, p.Conditions.Applications.IncludeApplications)
		assert.Equal(t, []string{"Office365"}, p.Conditions.Applications.ExcludeApplications)

		// Client app types — exactly exchangeActiveSync and other
		assert.Len(t, p.Conditions.ClientAppTypes, 2)
		assert.Contains(t, p.Conditions.ClientAppTypes, "exchangeActiveSync")
		assert.Contains(t, p.Conditions.ClientAppTypes, "other")

		// Risk levels — none
		assert.Empty(t, p.Conditions.SignInRiskLevels)
		assert.Empty(t, p.Conditions.UserRiskLevels)

		// No platforms, no locations
		assert.Nil(t, p.Conditions.Platforms)
		assert.Nil(t, p.Conditions.Locations)

		// Grant — must be OR with exactly block
		assert.Equal(t, "OR", p.GrantControls["operator"])
		assert.Equal(t, []string{"block"}, builtIn(p.GrantControls))

		// Session — applicationEnforcedRestrictions
		require.NotNil(t, p.SessionControls)
		assert.NotNil(t, p.SessionControls["applicationEnforcedRestrictions"])

		// Resolution: 1 user, 0 groups, 0 roles, 1 application
		assert.Len(t, p.ResolvedUsers, 1)
		assert.Empty(t, p.ResolvedGroups)
		assert.Empty(t, p.ResolvedRoles)
		assert.Len(t, p.ResolvedApplications, 1)
		assertUser(t, p, "test_user_object_id", "test_user_display_name", "test_user_upn")
		assertApp(t, p, "test_app_client_id", "test_app_display_name")
	})

	// =====================================================================
	// POLICY 5: Location-based (disabled)
	// =====================================================================
	t.Run("Policy5_LocationBased", func(t *testing.T) {
		p := fp["location_based"]
		assert.Equal(t, fixture.Output("location_based_policy_id"), p.ID)
		assert.Equal(t, "disabled", p.State)

		// Users
		require.NotNil(t, p.Conditions.Users)
		assert.Equal(t, []string{"All"}, p.Conditions.Users.IncludeUsers)
		assert.Contains(t, p.Conditions.Users.ExcludeUsers, "GuestsOrExternalUsers")
		assert.Equal(t, []string{fixture.Output("test_group_object_id")}, p.Conditions.Users.IncludeGroups)
		assert.Empty(t, p.Conditions.Users.ExcludeGroups)
		assert.Empty(t, p.Conditions.Users.IncludeRoles)
		assert.Empty(t, p.Conditions.Users.ExcludeRoles)

		// Applications
		assert.Equal(t, []string{"All"}, p.Conditions.Applications.IncludeApplications)
		assert.Empty(t, p.Conditions.Applications.ExcludeApplications)

		// Client app types
		assert.Equal(t, []string{"all"}, p.Conditions.ClientAppTypes)

		// Risk levels — none
		assert.Empty(t, p.Conditions.SignInRiskLevels)
		assert.Empty(t, p.Conditions.UserRiskLevels)

		// Platforms — all, exclude iOS+macOS
		require.NotNil(t, p.Conditions.Platforms)
		assert.Equal(t, []string{"all"}, strSlice(p.Conditions.Platforms, "includePlatforms"))
		excPlat := strSlice(p.Conditions.Platforms, "excludePlatforms")
		assert.Len(t, excPlat, 2)
		assert.Contains(t, excPlat, "iOS")
		assert.Contains(t, excPlat, "macOS")

		// Locations — All, exclude AllTrusted + named location
		require.NotNil(t, p.Conditions.Locations)
		assert.Equal(t, []string{"All"}, strSlice(p.Conditions.Locations, "includeLocations"))
		excLoc := strSlice(p.Conditions.Locations, "excludeLocations")
		assert.Len(t, excLoc, 2)
		assert.Contains(t, excLoc, "AllTrusted")
		assert.Contains(t, excLoc, fixture.Output("named_location_id"))

		// Grant — must be OR with exactly mfa
		assert.Equal(t, "OR", p.GrantControls["operator"])
		assert.Equal(t, []string{"mfa"}, builtIn(p.GrantControls))

		// Session — signInFrequency
		require.NotNil(t, p.SessionControls)
		assert.NotNil(t, p.SessionControls["signInFrequency"])

		// Resolution: 0 users (All/Guests aren't UUIDs), 1 group, 0 roles, 0 apps
		assert.Empty(t, p.ResolvedUsers)
		assert.Len(t, p.ResolvedGroups, 1)
		assert.Empty(t, p.ResolvedRoles)
		assert.Empty(t, p.ResolvedApplications)
		assertGroup(t, p, "test_group_object_id", "test_group_display_name")
	})

	// =====================================================================
	// POLICY 6: Block legacy auth (enabled)
	// =====================================================================
	t.Run("Policy6_BlockLegacyAuth", func(t *testing.T) {
		p := fp["block_legacy_auth"]
		assert.Equal(t, fixture.Output("block_legacy_auth_policy_id"), p.ID)
		assert.Equal(t, "enabled", p.State)

		// Users
		require.NotNil(t, p.Conditions.Users)
		assert.Equal(t, []string{"All"}, p.Conditions.Users.IncludeUsers)
		assert.Equal(t, []string{fixture.Output("admin_user_object_id")}, p.Conditions.Users.ExcludeUsers)
		assert.Empty(t, p.Conditions.Users.IncludeGroups)
		assert.Empty(t, p.Conditions.Users.ExcludeGroups)
		assert.Empty(t, p.Conditions.Users.IncludeRoles)
		assert.Equal(t, []string{fixture.Output("global_admin_role_template_id")}, p.Conditions.Users.ExcludeRoles)

		// Applications
		assert.Equal(t, []string{"All"}, p.Conditions.Applications.IncludeApplications)
		assert.Empty(t, p.Conditions.Applications.ExcludeApplications)

		// Client app types — exactly EAS and other
		assert.Len(t, p.Conditions.ClientAppTypes, 2)
		assert.Contains(t, p.Conditions.ClientAppTypes, "exchangeActiveSync")
		assert.Contains(t, p.Conditions.ClientAppTypes, "other")

		// Risk levels — none
		assert.Empty(t, p.Conditions.SignInRiskLevels)
		assert.Empty(t, p.Conditions.UserRiskLevels)

		// No platforms, no locations
		assert.Nil(t, p.Conditions.Platforms)
		assert.Nil(t, p.Conditions.Locations)

		// Grant — must be OR with exactly block
		assert.Equal(t, "OR", p.GrantControls["operator"])
		assert.Equal(t, []string{"block"}, builtIn(p.GrantControls))

		// No session controls
		assert.Nil(t, p.SessionControls)

		// Resolution: 1 excluded user, 0 groups, 0 roles (excludeRoles is Global Admin
		// but that goes to ResolvedRoles), 0 apps
		assert.Len(t, p.ResolvedUsers, 1)
		assert.Empty(t, p.ResolvedGroups)
		assert.Len(t, p.ResolvedRoles, 1)
		assert.Empty(t, p.ResolvedApplications)
		assertUser(t, p, "admin_user_object_id", "admin_user_display_name", "admin_user_object_id")
		assertRole(t, p, "global_admin_role_template_id", "Global Administrator")
	})

	// =====================================================================
	// POLICY 7: Require password change (report-only)
	// =====================================================================
	t.Run("Policy7_RequirePasswordChange", func(t *testing.T) {
		p := fp["require_password_change"]
		assert.Equal(t, fixture.Output("require_password_change_policy_id"), p.ID)
		assert.Equal(t, "enabledForReportingButNotEnforced", p.State)

		// Users
		require.NotNil(t, p.Conditions.Users)
		assert.Equal(t, []string{"All"}, p.Conditions.Users.IncludeUsers)
		assert.Len(t, p.Conditions.Users.ExcludeUsers, 2)
		assert.Contains(t, p.Conditions.Users.ExcludeUsers, fixture.Output("test_user_object_id"))
		assert.Contains(t, p.Conditions.Users.ExcludeUsers, fixture.Output("exclude_user_object_id"))
		assert.Empty(t, p.Conditions.Users.IncludeGroups)
		assert.Equal(t, []string{fixture.Output("admin_group_object_id")}, p.Conditions.Users.ExcludeGroups)
		assert.Empty(t, p.Conditions.Users.IncludeRoles)
		assert.Empty(t, p.Conditions.Users.ExcludeRoles)

		// Applications
		assert.Equal(t, []string{"All"}, p.Conditions.Applications.IncludeApplications)
		assert.Empty(t, p.Conditions.Applications.ExcludeApplications)

		// Client app types
		assert.Equal(t, []string{"all"}, p.Conditions.ClientAppTypes)

		// Risk levels — userRisk high only, no signInRisk
		assert.Empty(t, p.Conditions.SignInRiskLevels)
		assert.Equal(t, []string{"high"}, p.Conditions.UserRiskLevels)

		// No platforms, no locations
		assert.Nil(t, p.Conditions.Platforms)
		assert.Nil(t, p.Conditions.Locations)

		// Grant — must be AND with exactly mfa+passwordChange
		assert.Equal(t, "AND", p.GrantControls["operator"])
		controls := builtIn(p.GrantControls)
		assert.Len(t, controls, 2)
		assert.Contains(t, controls, "mfa")
		assert.Contains(t, controls, "passwordChange")

		// No session controls
		assert.Nil(t, p.SessionControls)

		// Resolution: 2 excluded users, 1 excluded group, 0 roles, 0 apps
		assert.Len(t, p.ResolvedUsers, 2)
		assert.Len(t, p.ResolvedGroups, 1)
		assert.Empty(t, p.ResolvedRoles)
		assert.Empty(t, p.ResolvedApplications)
		assertUser(t, p, "test_user_object_id", "test_user_display_name", "test_user_upn")
		assertUser(t, p, "exclude_user_object_id", "exclude_user_display_name", "exclude_user_object_id")
		assertGroup(t, p, "admin_group_object_id", "admin_group_display_name")
	})

	// =====================================================================
	// POLICY 8: Azure management MFA (enabled)
	// =====================================================================
	t.Run("Policy8_AzureMgmtMFA", func(t *testing.T) {
		p := fp["azure_mgmt_mfa"]
		assert.Equal(t, fixture.Output("azure_mgmt_mfa_policy_id"), p.ID)
		assert.Equal(t, "enabled", p.State)

		// Users
		require.NotNil(t, p.Conditions.Users)
		assert.Equal(t, []string{"All"}, p.Conditions.Users.IncludeUsers)
		assert.Empty(t, p.Conditions.Users.ExcludeUsers)
		assert.Empty(t, p.Conditions.Users.IncludeGroups)
		assert.Equal(t, []string{fixture.Output("admin_group_object_id")}, p.Conditions.Users.ExcludeGroups)
		assert.Len(t, p.Conditions.Users.IncludeRoles, 3)
		assert.Contains(t, p.Conditions.Users.IncludeRoles, fixture.Output("global_admin_role_template_id"))
		assert.Contains(t, p.Conditions.Users.IncludeRoles, fixture.Output("security_admin_role_template_id"))
		assert.Contains(t, p.Conditions.Users.IncludeRoles, fixture.Output("user_admin_role_template_id"))
		assert.Empty(t, p.Conditions.Users.ExcludeRoles)

		// Applications — exactly Azure Management app
		assert.Equal(t, []string{fixture.Output("azure_management_app_id")}, p.Conditions.Applications.IncludeApplications)
		assert.Empty(t, p.Conditions.Applications.ExcludeApplications)

		// Client app types
		assert.Equal(t, []string{"all"}, p.Conditions.ClientAppTypes)

		// Risk levels — none
		assert.Empty(t, p.Conditions.SignInRiskLevels)
		assert.Empty(t, p.Conditions.UserRiskLevels)

		// No platforms, no locations
		assert.Nil(t, p.Conditions.Platforms)
		assert.Nil(t, p.Conditions.Locations)

		// Grant — must be OR with exactly mfa
		assert.Equal(t, "OR", p.GrantControls["operator"])
		assert.Equal(t, []string{"mfa"}, builtIn(p.GrantControls))

		// No session controls
		assert.Nil(t, p.SessionControls)

		// Resolution: 0 users, 1 excluded group, 3 roles, 1 application
		assert.Empty(t, p.ResolvedUsers)
		assert.Len(t, p.ResolvedGroups, 1)
		assert.Len(t, p.ResolvedRoles, 3)
		assert.Len(t, p.ResolvedApplications, 1)
		assertGroup(t, p, "admin_group_object_id", "admin_group_display_name")
		assertRole(t, p, "global_admin_role_template_id", "Global Administrator")
		assertRole(t, p, "security_admin_role_template_id", "Security Administrator")
		assertRole(t, p, "user_admin_role_template_id", "User Administrator")
		// Azure Management app — well-known Microsoft app
		aid := fixture.Output("azure_management_app_id")
		require.Contains(t, p.ResolvedApplications, aid)
		e := p.ResolvedApplications[aid]
		assert.Equal(t, "application", e.Type)
		assert.Equal(t, aid, e.ID)
		assert.NotEmpty(t, e.DisplayName)
	})

	// =====================================================================
	// POLICY 9: Mobile approved apps (disabled)
	// =====================================================================
	t.Run("Policy9_MobileApprovedApps", func(t *testing.T) {
		p := fp["mobile_approved_apps"]
		assert.Equal(t, fixture.Output("mobile_approved_apps_policy_id"), p.ID)
		assert.Equal(t, "disabled", p.State)

		// Users — group-only, no explicit users
		require.NotNil(t, p.Conditions.Users)
		assert.Empty(t, p.Conditions.Users.IncludeUsers)
		assert.Empty(t, p.Conditions.Users.ExcludeUsers)
		assert.Equal(t, []string{fixture.Output("test_group_object_id")}, p.Conditions.Users.IncludeGroups)
		assert.Empty(t, p.Conditions.Users.ExcludeGroups)
		assert.Empty(t, p.Conditions.Users.IncludeRoles)
		assert.Empty(t, p.Conditions.Users.ExcludeRoles)

		// Applications — exactly Office365
		assert.Equal(t, []string{"Office365"}, p.Conditions.Applications.IncludeApplications)
		assert.Empty(t, p.Conditions.Applications.ExcludeApplications)

		// Client app types — exactly browser+mobileAppsAndDesktopClients
		assert.Len(t, p.Conditions.ClientAppTypes, 2)
		assert.Contains(t, p.Conditions.ClientAppTypes, "browser")
		assert.Contains(t, p.Conditions.ClientAppTypes, "mobileAppsAndDesktopClients")

		// Risk levels — none
		assert.Empty(t, p.Conditions.SignInRiskLevels)
		assert.Empty(t, p.Conditions.UserRiskLevels)

		// Platforms — exactly android+iOS, no excludes
		require.NotNil(t, p.Conditions.Platforms)
		incPlat := strSlice(p.Conditions.Platforms, "includePlatforms")
		assert.Len(t, incPlat, 2)
		assert.Contains(t, incPlat, "android")
		assert.Contains(t, incPlat, "iOS")
		assert.Empty(t, strSlice(p.Conditions.Platforms, "excludePlatforms"))

		// No locations
		assert.Nil(t, p.Conditions.Locations)

		// Grant — must be OR with exactly approvedApplication+compliantApplication
		assert.Equal(t, "OR", p.GrantControls["operator"])
		controls := builtIn(p.GrantControls)
		assert.Len(t, controls, 2)
		assert.Contains(t, controls, "approvedApplication")
		assert.Contains(t, controls, "compliantApplication")

		// No session controls
		assert.Nil(t, p.SessionControls)

		// Resolution: 0 users, 1 group (Office365 isn't a UUID), 0 roles, 0 apps
		assert.Empty(t, p.ResolvedUsers)
		assert.Len(t, p.ResolvedGroups, 1)
		assert.Empty(t, p.ResolvedRoles)
		assert.Empty(t, p.ResolvedApplications)
		assertGroup(t, p, "test_group_object_id", "test_group_display_name")
	})

	// =====================================================================
	// POLICY 10: Guest access (report-only)
	// =====================================================================
	t.Run("Policy10_GuestAccess", func(t *testing.T) {
		p := fp["guest_access"]
		assert.Equal(t, fixture.Output("guest_access_policy_id"), p.ID)
		assert.Equal(t, "enabledForReportingButNotEnforced", p.State)

		// Users
		require.NotNil(t, p.Conditions.Users)
		assert.Equal(t, []string{"GuestsOrExternalUsers"}, p.Conditions.Users.IncludeUsers)
		assert.Equal(t, []string{fixture.Output("admin_user_object_id")}, p.Conditions.Users.ExcludeUsers)
		assert.Empty(t, p.Conditions.Users.IncludeGroups)
		assert.Empty(t, p.Conditions.Users.ExcludeGroups)
		assert.Empty(t, p.Conditions.Users.IncludeRoles)
		assert.Empty(t, p.Conditions.Users.ExcludeRoles)

		// Applications — exactly Office365
		assert.Equal(t, []string{"Office365"}, p.Conditions.Applications.IncludeApplications)
		assert.Empty(t, p.Conditions.Applications.ExcludeApplications)

		// Client app types
		assert.Equal(t, []string{"all"}, p.Conditions.ClientAppTypes)

		// Risk levels — signIn low+medium, no userRisk
		assert.Len(t, p.Conditions.SignInRiskLevels, 2)
		assert.Contains(t, p.Conditions.SignInRiskLevels, "low")
		assert.Contains(t, p.Conditions.SignInRiskLevels, "medium")
		assert.Empty(t, p.Conditions.UserRiskLevels)

		// Platforms — all, no excludes
		require.NotNil(t, p.Conditions.Platforms)
		assert.Equal(t, []string{"all"}, strSlice(p.Conditions.Platforms, "includePlatforms"))
		assert.Empty(t, strSlice(p.Conditions.Platforms, "excludePlatforms"))

		// Locations — All, exclude AllTrusted
		require.NotNil(t, p.Conditions.Locations)
		assert.Equal(t, []string{"All"}, strSlice(p.Conditions.Locations, "includeLocations"))
		assert.Equal(t, []string{"AllTrusted"}, strSlice(p.Conditions.Locations, "excludeLocations"))

		// Grant — must be OR with exactly mfa
		assert.Equal(t, "OR", p.GrantControls["operator"])
		assert.Equal(t, []string{"mfa"}, builtIn(p.GrantControls))

		// Session — signInFrequency only
		require.NotNil(t, p.SessionControls)
		assert.NotNil(t, p.SessionControls["signInFrequency"])

		// Resolution: 1 excluded user (admin), 0 groups, 0 roles, 0 apps
		// (GuestsOrExternalUsers isn't a UUID, Office365 isn't a UUID)
		assert.Len(t, p.ResolvedUsers, 1)
		assert.Empty(t, p.ResolvedGroups)
		assert.Empty(t, p.ResolvedRoles)
		assert.Empty(t, p.ResolvedApplications)
		assertUser(t, p, "admin_user_object_id", "admin_user_display_name", "admin_user_object_id")
	})

	// =====================================================================
	// Fixture state distribution
	// =====================================================================
	t.Run("fixture policies cover all three states with exact counts", func(t *testing.T) {
		states := make(map[string]int)
		for _, key := range policyKeys {
			states[fp[key].State]++
		}
		assert.Equal(t, 5, states["disabled"])
		assert.Equal(t, 2, states["enabled"])
		assert.Equal(t, 3, states["enabledForReportingButNotEnforced"])
	})

	// =====================================================================
	// Cross-policy: all 10 fixture policy IDs discovered, no duplicates
	// =====================================================================
	t.Run("all 10 fixture policy IDs discovered", func(t *testing.T) {
		for _, id := range fixture.OutputList("all_policy_ids") {
			testutil.AssertResultContainsString(t, results, id)
		}
	})

	t.Run("no duplicate policy IDs", func(t *testing.T) {
		seen := make(map[string]int)
		for _, p := range policies {
			seen[p.ID]++
		}
		for id, count := range seen {
			assert.Equal(t, 1, count, "policy ID %q appears %d times", id, count)
		}
	})

	t.Run("no duplicate results", func(t *testing.T) {
		testutil.AssertNoDuplicateResults(t, results)
	})

	// =====================================================================
	// Structural validation for EVERY policy (fixture + pre-existing)
	// =====================================================================

	validStates := map[string]bool{
		"enabled": true, "disabled": true,
		"enabledForReportingButNotEnforced": true, "unknown": true,
	}
	validClientAppTypes := map[string]bool{
		"all": true, "browser": true, "mobileAppsAndDesktopClients": true,
		"exchangeActiveSync": true, "easSupported": true, "other": true,
	}
	validGrantControls := map[string]bool{
		"block": true, "mfa": true, "approvedApplication": true,
		"compliantApplication": true, "compliantDevice": true,
		"domainJoinedDevice": true, "passwordChange": true, "unknownFutureValue": true,
	}
	validPlatforms := map[string]bool{
		"android": true, "iOS": true, "windows": true, "windowsPhone": true,
		"macOS": true, "all": true, "unknownFutureValue": true, "linux": true,
	}
	validRiskLevels := map[string]bool{
		"low": true, "medium": true, "high": true,
		"hidden": true, "none": true, "unknownFutureValue": true,
	}

	for _, p := range policies {
		pName := p.DisplayName
		t.Run("StructuralValidation/"+pName, func(t *testing.T) {
			assert.NotEmpty(t, p.ID)
			assert.NotEmpty(t, p.DisplayName)
			assert.True(t, validStates[p.State], "invalid state %q", p.State)

			// JSON round-trip
			data, err := json.Marshal(p)
			require.NoError(t, err)
			var decoded output.AzureConditionalAccessPolicy
			require.NoError(t, json.Unmarshal(data, &decoded))
			assert.Equal(t, p.ID, decoded.ID)
			assert.Equal(t, p.DisplayName, decoded.DisplayName)
			assert.Equal(t, p.State, decoded.State)

			// Conditions must exist with users and apps
			require.NotNil(t, p.Conditions)
			require.NotNil(t, p.Conditions.Users)
			require.NotNil(t, p.Conditions.Applications)

			// clientAppTypes all valid
			require.NotEmpty(t, p.Conditions.ClientAppTypes)
			for _, cat := range p.Conditions.ClientAppTypes {
				assert.True(t, validClientAppTypes[cat], "invalid clientAppType %q", cat)
			}

			// Risk levels valid
			for _, rl := range p.Conditions.SignInRiskLevels {
				assert.True(t, validRiskLevels[rl], "invalid signInRiskLevel %q", rl)
			}
			for _, rl := range p.Conditions.UserRiskLevels {
				assert.True(t, validRiskLevels[rl], "invalid userRiskLevel %q", rl)
			}

			// Platforms valid
			if p.Conditions.Platforms != nil {
				for _, key := range []string{"includePlatforms", "excludePlatforms"} {
					for _, plat := range strSlice(p.Conditions.Platforms, key) {
						assert.True(t, validPlatforms[plat], "invalid platform %q", plat)
					}
				}
			}

			// Grant controls
			require.NotNil(t, p.GrantControls)
			op, _ := p.GrantControls["operator"].(string)
			assert.Contains(t, []string{"OR", "AND"}, op)
			for _, c := range builtIn(p.GrantControls) {
				assert.True(t, validGrantControls[c], "invalid builtInControl %q", c)
			}

			// Resolution completeness: every UUID is resolved
			allUserIDs := append(append([]string{}, p.Conditions.Users.IncludeUsers...), p.Conditions.Users.ExcludeUsers...)
			for _, uid := range allUserIDs {
				if uid == "All" || uid == "None" || uid == "GuestsOrExternalUsers" || uid == "" {
					continue
				}
				require.Contains(t, p.ResolvedUsers, uid, "user %s not resolved", uid)
				assert.Equal(t, "user", p.ResolvedUsers[uid].Type)
				assert.Equal(t, uid, p.ResolvedUsers[uid].ID)
				assert.NotEmpty(t, p.ResolvedUsers[uid].DisplayName)
				assert.NotEmpty(t, p.ResolvedUsers[uid].ExtraInfo["userPrincipalName"],
					"user %s missing UPN", uid)
			}

			allGroupIDs := append(append([]string{}, p.Conditions.Users.IncludeGroups...), p.Conditions.Users.ExcludeGroups...)
			for _, gid := range allGroupIDs {
				require.Contains(t, p.ResolvedGroups, gid, "group %s not resolved", gid)
				assert.Equal(t, "group", p.ResolvedGroups[gid].Type)
				assert.Equal(t, gid, p.ResolvedGroups[gid].ID)
				assert.NotEmpty(t, p.ResolvedGroups[gid].DisplayName)
			}

			allRoleIDs := append(append([]string{}, p.Conditions.Users.IncludeRoles...), p.Conditions.Users.ExcludeRoles...)
			for _, rid := range allRoleIDs {
				require.Contains(t, p.ResolvedRoles, rid, "role %s not resolved", rid)
				assert.Equal(t, "role", p.ResolvedRoles[rid].Type)
				assert.Equal(t, rid, p.ResolvedRoles[rid].ID)
				assert.NotEmpty(t, p.ResolvedRoles[rid].DisplayName)
				assert.NotEmpty(t, p.ResolvedRoles[rid].ExtraInfo["roleTemplateId"])
			}

			allAppIDs := append(append([]string{}, p.Conditions.Applications.IncludeApplications...), p.Conditions.Applications.ExcludeApplications...)
			for _, aid := range allAppIDs {
				if aid == "All" || aid == "None" || aid == "Office365" || aid == "" {
					continue
				}
				require.Contains(t, p.ResolvedApplications, aid, "application %s not resolved", aid)
				assert.Equal(t, "application", p.ResolvedApplications[aid].Type)
				assert.Equal(t, aid, p.ResolvedApplications[aid].ID)
				assert.NotEmpty(t, p.ResolvedApplications[aid].DisplayName)
			}
		})
	}
}
