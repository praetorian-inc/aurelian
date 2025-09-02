package azure

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionalAccessPolicyResult_BasicFields(t *testing.T) {
	policy := ConditionalAccessPolicyResult{
		ID:               "12345678-1234-1234-1234-123456789012",
		DisplayName:      "Test Policy",
		State:            "enabled",
		CreatedDateTime:  "2024-01-15T10:30:00Z",
		ModifiedDateTime: "2024-01-16T14:45:00Z",
	}

	assert.Equal(t, "12345678-1234-1234-1234-123456789012", policy.ID)
	assert.Equal(t, "Test Policy", policy.DisplayName)
	assert.Equal(t, "enabled", policy.State)
	assert.Equal(t, "2024-01-15T10:30:00Z", policy.CreatedDateTime)
	assert.Equal(t, "2024-01-16T14:45:00Z", policy.ModifiedDateTime)
}

func TestConditionalAccessPolicyResult_WithConditions(t *testing.T) {
	policy := ConditionalAccessPolicyResult{
		ID:          "test-policy-id",
		DisplayName: "Test Policy with Conditions",
		State:       "enabled",
		Conditions: &ConditionalAccessConditionSet{
			Users: &ConditionalAccessUsers{
				IncludeUsers:  []string{"user1", "user2"},
				ExcludeUsers:  []string{"admin1"},
				IncludeGroups: []string{"group1"},
				ExcludeGroups: []string{"admingroup1"},
			},
			Applications: &ConditionalAccessApplications{
				IncludeApplications: []string{"All"},
				ExcludeApplications: []string{"trusted-app-id"},
			},
			ClientAppTypes:   []string{"browser", "mobileAppsAndDesktopClients"},
			SignInRiskLevels: []string{"medium", "high"},
		},
	}

	require.NotNil(t, policy.Conditions)
	require.NotNil(t, policy.Conditions.Users)
	require.NotNil(t, policy.Conditions.Applications)

	assert.Equal(t, []string{"user1", "user2"}, policy.Conditions.Users.IncludeUsers)
	assert.Equal(t, []string{"admin1"}, policy.Conditions.Users.ExcludeUsers)
	assert.Equal(t, []string{"group1"}, policy.Conditions.Users.IncludeGroups)
	assert.Equal(t, []string{"admingroup1"}, policy.Conditions.Users.ExcludeGroups)
	assert.Equal(t, []string{"All"}, policy.Conditions.Applications.IncludeApplications)
	assert.Equal(t, []string{"trusted-app-id"}, policy.Conditions.Applications.ExcludeApplications)
	assert.Equal(t, []string{"browser", "mobileAppsAndDesktopClients"}, policy.Conditions.ClientAppTypes)
	assert.Equal(t, []string{"medium", "high"}, policy.Conditions.SignInRiskLevels)
}

func TestResolvedEntity_UserEntity(t *testing.T) {
	entity := ResolvedEntity{
		ID:          "87d349ed-44d7-43e1-9a83-5f2406dee5bd",
		Type:        "user",
		DisplayName: "Adele Vance",
		ExtraInfo: map[string]string{
			"userPrincipalName": "AdeleV@contoso.com",
			"mail":              "adele.vance@contoso.com",
		},
	}

	assert.Equal(t, "87d349ed-44d7-43e1-9a83-5f2406dee5bd", entity.ID)
	assert.Equal(t, "user", entity.Type)
	assert.Equal(t, "Adele Vance", entity.DisplayName)
	assert.Equal(t, "AdeleV@contoso.com", entity.ExtraInfo["userPrincipalName"])
	assert.Equal(t, "adele.vance@contoso.com", entity.ExtraInfo["mail"])
}

func TestResolvedEntity_GroupEntity(t *testing.T) {
	entity := ResolvedEntity{
		ID:          "6c96716b-b32b-40b8-9009-49748bb6fcd5",
		Type:        "group",
		DisplayName: "HR Team",
		Description: "Human Resources department group",
		ExtraInfo: map[string]string{
			"mail": "hr@contoso.com",
		},
	}

	assert.Equal(t, "6c96716b-b32b-40b8-9009-49748bb6fcd5", entity.ID)
	assert.Equal(t, "group", entity.Type)
	assert.Equal(t, "HR Team", entity.DisplayName)
	assert.Equal(t, "Human Resources department group", entity.Description)
	assert.Equal(t, "hr@contoso.com", entity.ExtraInfo["mail"])
}

func TestResolvedEntity_ApplicationEntity(t *testing.T) {
	entity := ResolvedEntity{
		ID:          "00000003-0000-0000-c000-000000000000",
		Type:        "application",
		DisplayName: "Microsoft Graph",
		Description: "Microsoft Graph API",
		ExtraInfo: map[string]string{
			"appId": "00000003-0000-0000-c000-000000000000",
		},
	}

	assert.Equal(t, "00000003-0000-0000-c000-000000000000", entity.ID)
	assert.Equal(t, "application", entity.Type)
	assert.Equal(t, "Microsoft Graph", entity.DisplayName)
	assert.Equal(t, "Microsoft Graph API", entity.Description)
	assert.Equal(t, "00000003-0000-0000-c000-000000000000", entity.ExtraInfo["appId"])
}

func TestEnrichedConditionalAccessPolicy_WithResolvedEntities(t *testing.T) {
	// Create original policy
	originalPolicy := ConditionalAccessPolicyResult{
		ID:          "policy-123",
		DisplayName: "Test Enriched Policy",
		State:       "enabled",
		Conditions: &ConditionalAccessConditionSet{
			Users: &ConditionalAccessUsers{
				IncludeUsers:  []string{"user1"},
				IncludeGroups: []string{"group1"},
			},
			Applications: &ConditionalAccessApplications{
				IncludeApplications: []string{"app1"},
			},
		},
	}

	// Create enriched policy with resolved entities
	enrichedPolicy := EnrichedConditionalAccessPolicy{
		ConditionalAccessPolicyResult: originalPolicy,
		ResolvedUsers: map[string]ResolvedEntity{
			"user1": {
				ID:          "user1",
				Type:        "user",
				DisplayName: "John Doe",
			},
		},
		ResolvedGroups: map[string]ResolvedEntity{
			"group1": {
				ID:          "group1",
				Type:        "group",
				DisplayName: "Sales Team",
			},
		},
		ResolvedApplications: map[string]ResolvedEntity{
			"app1": {
				ID:          "app1",
				Type:        "application",
				DisplayName: "Salesforce",
			},
		},
		ResolvedRoles: map[string]ResolvedEntity{},
	}

	// Verify the enriched policy structure
	assert.Equal(t, "policy-123", enrichedPolicy.ID)
	assert.Equal(t, "Test Enriched Policy", enrichedPolicy.DisplayName)
	assert.Equal(t, "enabled", enrichedPolicy.State)

	// Verify resolved entities
	assert.Len(t, enrichedPolicy.ResolvedUsers, 1)
	assert.Equal(t, "John Doe", enrichedPolicy.ResolvedUsers["user1"].DisplayName)

	assert.Len(t, enrichedPolicy.ResolvedGroups, 1)
	assert.Equal(t, "Sales Team", enrichedPolicy.ResolvedGroups["group1"].DisplayName)

	assert.Len(t, enrichedPolicy.ResolvedApplications, 1)
	assert.Equal(t, "Salesforce", enrichedPolicy.ResolvedApplications["app1"].DisplayName)

	assert.Len(t, enrichedPolicy.ResolvedRoles, 0)
}

func TestAzureConditionalAccessOutputFormatterLink_FormatPolicyState(t *testing.T) {
	formatter := &AzureConditionalAccessOutputFormatterLink{}

	tests := []struct {
		input    string
		expected string
	}{
		{"enabled", "Enabled"},
		{"disabled", "Disabled"},
		{"enabledForReportingButNotEnforced", "Report-only"},
		{"unknown", "Unknown"},
		{"", ""},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := formatter.formatPolicyState(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestAzureConditionalAccessOutputFormatterLink_FormatPolicyStateWithIcon(t *testing.T) {
	formatter := &AzureConditionalAccessOutputFormatterLink{}

	tests := []struct {
		input    string
		expected string
	}{
		{"enabled", "✅ **Enabled**"},
		{"disabled", "❌ **Disabled**"},
		{"enabledForReportingButNotEnforced", "📊 **Report-only**"},
		{"unknown", "❓ **Unknown**"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := formatter.formatPolicyStateWithIcon(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestAzureConditionalAccessOutputFormatterLink_FormatDateTime(t *testing.T) {
	formatter := &AzureConditionalAccessOutputFormatterLink{}

	tests := []struct {
		input    string
		expected string
	}{
		{"2024-01-15T10:30:00Z", "2024-01-15 10:30:00 UTC"},
		{"2024-12-25T23:59:59Z", "2024-12-25 23:59:59 UTC"},
		{"invalid-datetime", "invalid-datetime"}, // Should return original string if parsing fails
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := formatter.formatDateTime(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestAzureConditionalAccessOutputFormatterLink_FormatPlatform(t *testing.T) {
	formatter := &AzureConditionalAccessOutputFormatterLink{}

	tests := []struct {
		input    string
		expected string
	}{
		{"all", "All devices"},
		{"android", "Android"},
		{"iOS", "iOS"},
		{"windows", "Windows"},
		{"windowsPhone", "Windows Phone"},
		{"macOS", "macOS"},
		{"unknown", "unknown"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := formatter.formatPlatform(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestAzureConditionalAccessOutputFormatterLink_FormatClientAppType(t *testing.T) {
	formatter := &AzureConditionalAccessOutputFormatterLink{}

	tests := []struct {
		input    string
		expected string
	}{
		{"all", "All client apps"},
		{"browser", "Browser"},
		{"mobileAppsAndDesktopClients", "Mobile apps and desktop clients"},
		{"exchangeActiveSync", "Exchange ActiveSync clients"},
		{"easSupported", "Exchange ActiveSync supported clients"},
		{"other", "Other clients"},
		{"unknown", "unknown"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := formatter.formatClientAppType(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestAzureConditionalAccessOutputFormatterLink_FormatBuiltInControl(t *testing.T) {
	formatter := &AzureConditionalAccessOutputFormatterLink{}

	tests := []struct {
		input    string
		expected string
	}{
		{"block", "Block access"},
		{"mfa", "Require multi-factor authentication"},
		{"compliantDevice", "Require device to be marked as compliant"},
		{"domainJoinedDevice", "Require domain joined device"},
		{"approvedApplication", "Require approved client app"},
		{"compliantApplication", "Require app protection policy"},
		{"unknown", "unknown"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := formatter.formatBuiltInControl(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestFilterValidUUIDs(t *testing.T) {
	resolver := &AzureConditionalAccessResolverLink{}

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "Valid UUIDs only",
			input:    []string{"12345678-1234-1234-1234-123456789012", "87654321-4321-4321-4321-210987654321"},
			expected: []string{"12345678-1234-1234-1234-123456789012", "87654321-4321-4321-4321-210987654321"},
		},
		{
			name:     "Mixed valid and special values",
			input:    []string{"All", "None", "12345678-1234-1234-1234-123456789012", "GuestsOrExternalUsers"},
			expected: []string{"12345678-1234-1234-1234-123456789012"},
		},
		{
			name:     "Only special values",
			input:    []string{"All", "None", "GuestsOrExternalUsers", ""},
			expected: []string{},
		},
		{
			name:     "Invalid UUID format",
			input:    []string{"invalid-uuid", "short-uuid", "12345678123412341234123456789012"}, // No dashes
			expected: []string{},
		},
		{
			name:     "Empty input",
			input:    []string{},
			expected: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := resolver.filterValidUUIDs(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestUUIDResolver_Cache(t *testing.T) {
	resolver := NewUUIDResolver(nil) // nil client for this test

	// Manually add an entity to cache
	testEntity := ResolvedEntity{
		ID:          "test-uuid-123",
		Type:        "user",
		DisplayName: "Test User",
	}

	resolver.cacheMu.Lock()
	resolver.cache["test-uuid-123"] = testEntity
	resolver.cacheMu.Unlock()

	// Verify cache retrieval
	resolver.cacheMu.RLock()
	cached, exists := resolver.cache["test-uuid-123"]
	resolver.cacheMu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, testEntity, cached)
	assert.Equal(t, "Test User", cached.DisplayName)
	assert.Equal(t, "user", cached.Type)
}

func TestCreateHumanReadableMarkdown_EmptyPolicies(t *testing.T) {
	formatter := &AzureConditionalAccessOutputFormatterLink{}
	
	policies := []EnrichedConditionalAccessPolicy{}
	markdown := formatter.createHumanReadableMarkdown(policies)
	
	// Should contain basic structure even with no policies
	assert.Contains(t, markdown, "# Azure Conditional Access Policies Report")
	assert.Contains(t, markdown, "**Total Policies**: 0")
	assert.Contains(t, markdown, "## Policy Summary")
}

func TestCreateHumanReadableMarkdown_SinglePolicy(t *testing.T) {
	formatter := &AzureConditionalAccessOutputFormatterLink{}
	
	policies := []EnrichedConditionalAccessPolicy{
		{
			ConditionalAccessPolicyResult: ConditionalAccessPolicyResult{
				ID:          "policy-123",
				DisplayName: "Test Policy",
				State:       "enabled",
			},
			ResolvedUsers:        map[string]ResolvedEntity{},
			ResolvedGroups:       map[string]ResolvedEntity{},
			ResolvedApplications: map[string]ResolvedEntity{},
			ResolvedRoles:        map[string]ResolvedEntity{},
		},
	}
	
	markdown := formatter.createHumanReadableMarkdown(policies)
	
	assert.Contains(t, markdown, "**Total Policies**: 1")
	assert.Contains(t, markdown, "Test Policy")
	assert.Contains(t, markdown, "policy-123")
	assert.Contains(t, markdown, "### 1. Test Policy")
}

// Benchmark tests for performance
func BenchmarkFilterValidUUIDs(b *testing.B) {
	resolver := &AzureConditionalAccessResolverLink{}
	uuids := []string{
		"12345678-1234-1234-1234-123456789012",
		"All",
		"87654321-4321-4321-4321-210987654321",
		"None",
		"invalid-uuid",
		"abcdefab-cdef-1234-5678-abcdefabcdef",
		"GuestsOrExternalUsers",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolver.filterValidUUIDs(uuids)
	}
}

func BenchmarkCreateHumanReadableMarkdown(b *testing.B) {
	formatter := &AzureConditionalAccessOutputFormatterLink{}
	
	// Create a realistic set of policies for benchmarking
	policies := make([]EnrichedConditionalAccessPolicy, 10)
	for i := 0; i < 10; i++ {
		policies[i] = EnrichedConditionalAccessPolicy{
			ConditionalAccessPolicyResult: ConditionalAccessPolicyResult{
				ID:          fmt.Sprintf("policy-%d", i),
				DisplayName: fmt.Sprintf("Test Policy %d", i),
				State:       "enabled",
				Conditions: &ConditionalAccessConditionSet{
					Users: &ConditionalAccessUsers{
						IncludeUsers: []string{"user1", "user2"},
					},
					Applications: &ConditionalAccessApplications{
						IncludeApplications: []string{"All"},
					},
				},
			},
			ResolvedUsers: map[string]ResolvedEntity{
				"user1": {DisplayName: "John Doe", Type: "user"},
				"user2": {DisplayName: "Jane Doe", Type: "user"},
			},
			ResolvedGroups:       map[string]ResolvedEntity{},
			ResolvedApplications: map[string]ResolvedEntity{},
			ResolvedRoles:        map[string]ResolvedEntity{},
		}
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		formatter.createHumanReadableMarkdown(policies)
	}
}

// Example test that demonstrates the complete data flow
func TestCompleteDataFlow_Example(t *testing.T) {
	// This test demonstrates how data flows through all three links:
	// Collector -> Resolver -> Formatter
	
	// 1. Raw policy from collector
	rawPolicy := ConditionalAccessPolicyResult{
		ID:          "12345678-1234-1234-1234-123456789012",
		DisplayName: "Require MFA for All Users",
		State:       "enabled",
		CreatedDateTime:  time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339), // 30 days ago
		ModifiedDateTime: time.Now().Add(-1 * 24 * time.Hour).Format(time.RFC3339),  // 1 day ago
		Conditions: &ConditionalAccessConditionSet{
			Users: &ConditionalAccessUsers{
				IncludeUsers:  []string{"All"},
				ExcludeGroups: []string{"87654321-4321-4321-4321-210987654321"},
			},
			Applications: &ConditionalAccessApplications{
				IncludeApplications: []string{"All"},
			},
			ClientAppTypes:   []string{"browser", "mobileAppsAndDesktopClients"},
			SignInRiskLevels: []string{"medium", "high"},
		},
		GrantControls: map[string]interface{}{
			"operator":         "AND",
			"builtInControls": []interface{}{"mfa"},
		},
	}

	// 2. Enriched policy from resolver (simulated)
	enrichedPolicy := EnrichedConditionalAccessPolicy{
		ConditionalAccessPolicyResult: rawPolicy,
		ResolvedUsers:        map[string]ResolvedEntity{}, // "All" users - no specific resolution needed
		ResolvedGroups: map[string]ResolvedEntity{
			"87654321-4321-4321-4321-210987654321": {
				ID:          "87654321-4321-4321-4321-210987654321",
				Type:        "group",
				DisplayName: "Break Glass Accounts",
				Description: "Emergency access accounts",
			},
		},
		ResolvedApplications: map[string]ResolvedEntity{}, // "All" applications
		ResolvedRoles:        map[string]ResolvedEntity{},
	}

	// 3. Formatted output from formatter
	formatter := &AzureConditionalAccessOutputFormatterLink{}
	policies := []EnrichedConditionalAccessPolicy{enrichedPolicy}
	markdown := formatter.createHumanReadableMarkdown(policies)

	// Verify the complete flow produced expected results
	assert.Contains(t, markdown, "Require MFA for All Users")
	assert.Contains(t, markdown, "✅ **Enabled**")
	assert.Contains(t, markdown, "Break Glass Accounts")
	assert.Contains(t, markdown, "**All Cloud Apps**")
	assert.Contains(t, markdown, "Browser")
	assert.Contains(t, markdown, "Mobile apps and desktop clients")
	assert.Contains(t, markdown, "medium, high")

	// Verify JSON structure would be valid
	assert.Equal(t, "enabled", enrichedPolicy.State)
	assert.Equal(t, "12345678-1234-1234-1234-123456789012", enrichedPolicy.ID)
	assert.NotNil(t, enrichedPolicy.Conditions)
	assert.Len(t, enrichedPolicy.ResolvedGroups, 1)
}