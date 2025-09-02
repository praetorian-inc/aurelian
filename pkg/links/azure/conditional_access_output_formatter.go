package azure

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

type AzureConditionalAccessOutputFormatterLink struct {
	*chain.Base
}

func NewAzureConditionalAccessOutputFormatterLink(configs ...cfg.Config) chain.Link {
	l := &AzureConditionalAccessOutputFormatterLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureConditionalAccessOutputFormatterLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureWorkerCount(),
		options.OutputDir(),
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) Process(input any) error {
	// Expect input to be []EnrichedConditionalAccessPolicy from resolver
	enrichedPolicies, ok := input.([]EnrichedConditionalAccessPolicy)
	if !ok {
		return fmt.Errorf("expected []EnrichedConditionalAccessPolicy, got %T", input)
	}

	// Generate JSON output first
	if err := l.generateJSONOutput(enrichedPolicies); err != nil {
		return fmt.Errorf("failed to generate JSON output: %w", err)
	}

	// Generate console output (directly to stdout, not sent through pipeline)
	l.generateConsoleOutput(enrichedPolicies)

	return nil
}

func (l *AzureConditionalAccessOutputFormatterLink) generateJSONOutput(policies []EnrichedConditionalAccessPolicy) error {
	outputDir, _ := cfg.As[string](l.Arg("output"))

	// Get tenant ID for filename
	tenantID, err := l.getTenantID()
	var jsonFilePath string
	if err != nil {
		slog.Warn("Failed to get tenant ID, using timestamp instead", "error", err)
		timestamp := time.Now().Format("20060102-150405")
		filename := fmt.Sprintf("out-%s.json", timestamp)
		jsonFilePath = filepath.Join(outputDir, filename)
	} else {
		filename := fmt.Sprintf("conditional-access-policies-%s.json", tenantID)
		jsonFilePath = filepath.Join(outputDir, filename)
	}

	// Create structured output data with tenant ID if available
	metadata := map[string]interface{}{
		"collectedAt": time.Now().UTC().Format(time.RFC3339),
		"policyCount": len(policies),
		"module":      "conditional-access-policies",
	}
	if tenantID != "" {
		metadata["tenantId"] = tenantID
	}

	outputData := map[string]interface{}{
		"metadata": metadata,
		"policies": policies,
	}

	// Send JSON output
	jsonOutput := outputters.NewNamedOutputData(outputData, jsonFilePath)
	return l.Send(jsonOutput)
}

func (l *AzureConditionalAccessOutputFormatterLink) generateConsoleOutput(policies []EnrichedConditionalAccessPolicy) {
	// Print console table directly to stdout
	fmt.Printf("\nAzure Conditional Access Policies\n")
	fmt.Printf("| %-30s | %-15s | %-5s | %-6s | %-12s |\n",
		"Policy Name", "State", "Users", "Groups", "Applications")
	fmt.Printf("|%s|%s|%s|%s|%s|\n",
		"--------------------------------", "-----------------", "-------", "--------", "--------------")

	for _, policy := range policies {
		userCount := len(policy.ResolvedUsers)
		groupCount := len(policy.ResolvedGroups)
		appCount := len(policy.ResolvedApplications)

		// Truncate policy name if too long
		policyName := policy.DisplayName
		if len(policyName) > 30 {
			policyName = policyName[:27] + "..."
		}

		fmt.Printf("| %-30s | %-15s | %-5d | %-6d | %-12d |\n",
			policyName, l.formatPolicyState(policy.State), userCount, groupCount, appCount)
	}
	fmt.Printf("\nTotal policies: %d\n", len(policies))
}

func (l *AzureConditionalAccessOutputFormatterLink) generateMarkdownOutput(policies []EnrichedConditionalAccessPolicy) error {
	outputDir, _ := cfg.As[string](l.Arg("output"))

	// Create filename with timestamp - use same pattern as other modules
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("conditional-access-policies-%s.md", timestamp)
	mdFilePath := filepath.Join(outputDir, filename)

	// Generate human-readable markdown content
	markdown := l.createHumanReadableMarkdown(policies)

	// Send Markdown output
	mdOutput := outputters.NewNamedOutputData(markdown, mdFilePath)
	return l.Send(mdOutput)
}

func (l *AzureConditionalAccessOutputFormatterLink) createHumanReadableMarkdown(policies []EnrichedConditionalAccessPolicy) string {
	var md strings.Builder

	md.WriteString("# Azure Conditional Access Policies Report\n\n")
	md.WriteString(fmt.Sprintf("**Generated**: %s  \n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))
	md.WriteString(fmt.Sprintf("**Total Policies**: %d\n\n", len(policies)))

	// Sort policies by state and name for better readability
	sortedPolicies := make([]EnrichedConditionalAccessPolicy, len(policies))
	copy(sortedPolicies, policies)
	sort.Slice(sortedPolicies, func(i, j int) bool {
		if sortedPolicies[i].State != sortedPolicies[j].State {
			// Enabled policies first
			if sortedPolicies[i].State == "enabled" {
				return true
			}
			if sortedPolicies[j].State == "enabled" {
				return false
			}
		}
		return sortedPolicies[i].DisplayName < sortedPolicies[j].DisplayName
	})

	// Create summary table
	md.WriteString("## Policy Summary\n\n")
	md.WriteString("| Policy Name | State | Users | Groups | Applications |\n")
	md.WriteString("|-------------|-------|-------|--------|--------------|\n")

	for _, policy := range sortedPolicies {
		userCount := len(policy.ResolvedUsers)
		groupCount := len(policy.ResolvedGroups)
		appCount := len(policy.ResolvedApplications)

		md.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %d |\n",
			policy.DisplayName,
			l.formatPolicyState(policy.State),
			userCount,
			groupCount,
			appCount,
		))
	}

	md.WriteString("\n---\n\n")

	// Detailed policy information
	md.WriteString("## Detailed Policy Information\n\n")

	for i, policy := range sortedPolicies {
		md.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, policy.DisplayName))

		// Basic information
		md.WriteString(fmt.Sprintf("**Policy ID**: `%s`  \n", policy.ID))
		md.WriteString(fmt.Sprintf("**State**: %s  \n", l.formatPolicyStateWithIcon(policy.State)))

		if policy.TemplateID != nil && *policy.TemplateID != "" {
			md.WriteString(fmt.Sprintf("**Template ID**: `%s`  \n", *policy.TemplateID))
		}

		if policy.CreatedDateTime != "" {
			md.WriteString(fmt.Sprintf("**Created**: %s  \n", l.formatDateTime(policy.CreatedDateTime)))
		}

		if policy.ModifiedDateTime != "" {
			md.WriteString(fmt.Sprintf("**Last Modified**: %s  \n", l.formatDateTime(policy.ModifiedDateTime)))
		}

		md.WriteString("\n")

		// Conditions
		if policy.Conditions != nil {
			md.WriteString("#### Conditions\n\n")

			// Users and Groups
			l.formatUsersAndGroups(&md, &policy)

			// Applications
			l.formatApplications(&md, &policy)

			// Other conditions
			l.formatOtherConditions(&md, policy.Conditions)
		}

		// Grant Controls
		if policy.GrantControls != nil {
			md.WriteString("#### Grant Controls\n\n")
			l.formatGrantControls(&md, policy.GrantControls)
		}

		// Session Controls
		if policy.SessionControls != nil {
			md.WriteString("#### Session Controls\n\n")
			l.formatSessionControls(&md, policy.SessionControls)
		}

		md.WriteString("\n---\n\n")
	}

	return md.String()
}

func (l *AzureConditionalAccessOutputFormatterLink) formatUsersAndGroups(md *strings.Builder, policy *EnrichedConditionalAccessPolicy) {
	if policy.Conditions.Users == nil {
		return
	}

	users := policy.Conditions.Users

	// Include Users
	if len(users.IncludeUsers) > 0 {
		md.WriteString("**Include Users:**\n")
		for _, userID := range users.IncludeUsers {
			if userID == "All" {
				md.WriteString("- **All Users**\n")
			} else if resolved, exists := policy.ResolvedUsers[userID]; exists {
				upn := ""
				if resolved.ExtraInfo != nil && resolved.ExtraInfo["userPrincipalName"] != "" {
					upn = fmt.Sprintf(" (%s)", resolved.ExtraInfo["userPrincipalName"])
				}
				md.WriteString(fmt.Sprintf("- %s%s\n", resolved.DisplayName, upn))
			} else {
				md.WriteString(fmt.Sprintf("- Unknown User (%s)\n", userID))
			}
		}
		md.WriteString("\n")
	}

	// Include Groups
	if len(users.IncludeGroups) > 0 {
		md.WriteString("**Include Groups:**\n")
		for _, groupID := range users.IncludeGroups {
			if resolved, exists := policy.ResolvedGroups[groupID]; exists {
				description := ""
				if resolved.Description != "" {
					description = fmt.Sprintf(" - %s", resolved.Description)
				}
				md.WriteString(fmt.Sprintf("- %s%s\n", resolved.DisplayName, description))
			} else {
				md.WriteString(fmt.Sprintf("- Unknown Group (%s)\n", groupID))
			}
		}
		md.WriteString("\n")
	}

	// Include Roles
	if len(users.IncludeRoles) > 0 {
		md.WriteString("**Include Roles:**\n")
		for _, roleID := range users.IncludeRoles {
			if resolved, exists := policy.ResolvedRoles[roleID]; exists {
				md.WriteString(fmt.Sprintf("- %s\n", resolved.DisplayName))
			} else {
				md.WriteString(fmt.Sprintf("- Unknown Role (%s)\n", roleID))
			}
		}
		md.WriteString("\n")
	}

	// Exclude Users
	if len(users.ExcludeUsers) > 0 {
		md.WriteString("**Exclude Users:**\n")
		for _, userID := range users.ExcludeUsers {
			if resolved, exists := policy.ResolvedUsers[userID]; exists {
				upn := ""
				if resolved.ExtraInfo != nil && resolved.ExtraInfo["userPrincipalName"] != "" {
					upn = fmt.Sprintf(" (%s)", resolved.ExtraInfo["userPrincipalName"])
				}
				md.WriteString(fmt.Sprintf("- %s%s\n", resolved.DisplayName, upn))
			} else {
				md.WriteString(fmt.Sprintf("- Unknown User (%s)\n", userID))
			}
		}
		md.WriteString("\n")
	}

	// Exclude Groups
	if len(users.ExcludeGroups) > 0 {
		md.WriteString("**Exclude Groups:**\n")
		for _, groupID := range users.ExcludeGroups {
			if resolved, exists := policy.ResolvedGroups[groupID]; exists {
				md.WriteString(fmt.Sprintf("- %s\n", resolved.DisplayName))
			} else {
				md.WriteString(fmt.Sprintf("- Unknown Group (%s)\n", groupID))
			}
		}
		md.WriteString("\n")
	}

	// Exclude Roles
	if len(users.ExcludeRoles) > 0 {
		md.WriteString("**Exclude Roles:**\n")
		for _, roleID := range users.ExcludeRoles {
			if resolved, exists := policy.ResolvedRoles[roleID]; exists {
				md.WriteString(fmt.Sprintf("- %s\n", resolved.DisplayName))
			} else {
				md.WriteString(fmt.Sprintf("- Unknown Role (%s)\n", roleID))
			}
		}
		md.WriteString("\n")
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) formatApplications(md *strings.Builder, policy *EnrichedConditionalAccessPolicy) {
	if policy.Conditions.Applications == nil {
		return
	}

	apps := policy.Conditions.Applications

	// Include Applications
	if len(apps.IncludeApplications) > 0 {
		md.WriteString("**Include Applications:**\n")
		for _, appID := range apps.IncludeApplications {
			if appID == "All" {
				md.WriteString("- **All Cloud Apps**\n")
			} else if appID == "Office365" {
				md.WriteString("- **Microsoft Office 365**\n")
			} else if appID == "MicrosoftAdminPortals" {
				md.WriteString("- **Microsoft Admin Portals**\n")
			} else if resolved, exists := policy.ResolvedApplications[appID]; exists {
				appInfo := ""
				if resolved.ExtraInfo != nil && resolved.ExtraInfo["appId"] != "" {
					appInfo = fmt.Sprintf(" (App ID: %s)", resolved.ExtraInfo["appId"])
				}
				md.WriteString(fmt.Sprintf("- %s%s\n", resolved.DisplayName, appInfo))
			} else {
				md.WriteString(fmt.Sprintf("- Unknown Application (%s)\n", appID))
			}
		}
		md.WriteString("\n")
	}

	// Exclude Applications
	if len(apps.ExcludeApplications) > 0 {
		md.WriteString("**Exclude Applications:**\n")
		for _, appID := range apps.ExcludeApplications {
			if appID == "Office365" {
				md.WriteString("- **Microsoft Office 365**\n")
			} else if appID == "MicrosoftAdminPortals" {
				md.WriteString("- **Microsoft Admin Portals**\n")
			} else if resolved, exists := policy.ResolvedApplications[appID]; exists {
				md.WriteString(fmt.Sprintf("- %s\n", resolved.DisplayName))
			} else {
				md.WriteString(fmt.Sprintf("- Unknown Application (%s)\n", appID))
			}
		}
		md.WriteString("\n")
	}

	// User Actions
	if len(apps.IncludeUserActions) > 0 {
		md.WriteString("**Include User Actions:**\n")
		for _, action := range apps.IncludeUserActions {
			switch action {
			case "urn:user:registersecurityinfo":
				md.WriteString("- Register security information\n")
			case "urn:user:registerdevice":
				md.WriteString("- Register device\n")
			default:
				md.WriteString(fmt.Sprintf("- %s\n", action))
			}
		}
		md.WriteString("\n")
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) formatOtherConditions(md *strings.Builder, conditions *ConditionalAccessConditionSet) {
	// Locations
	if conditions.Locations != nil {
		if includeLocations, ok := conditions.Locations["includeLocations"].([]string); ok && len(includeLocations) > 0 {
			md.WriteString("**Include Locations:**\n")
			for _, location := range includeLocations {
				if location == "All" {
					md.WriteString("- Any location\n")
				} else if location == "AllTrusted" {
					md.WriteString("- All trusted locations\n")
				} else {
					md.WriteString(fmt.Sprintf("- %s\n", location))
				}
			}
			md.WriteString("\n")
		}

		if excludeLocations, ok := conditions.Locations["excludeLocations"].([]string); ok && len(excludeLocations) > 0 {
			md.WriteString("**Exclude Locations:**\n")
			for _, location := range excludeLocations {
				if location == "AllTrusted" {
					md.WriteString("- All trusted locations\n")
				} else {
					md.WriteString(fmt.Sprintf("- %s\n", location))
				}
			}
			md.WriteString("\n")
		}
	}

	// Platforms
	if conditions.Platforms != nil {
		if includePlatforms, ok := conditions.Platforms["includePlatforms"].([]string); ok && len(includePlatforms) > 0 {
			md.WriteString("**Include Platforms:**\n")
			for _, platform := range includePlatforms {
				md.WriteString(fmt.Sprintf("- %s\n", l.formatPlatform(platform)))
			}
			md.WriteString("\n")
		}
	}

	// Client App Types
	if len(conditions.ClientAppTypes) > 0 {
		md.WriteString("**Client App Types:**\n")
		for _, clientApp := range conditions.ClientAppTypes {
			md.WriteString(fmt.Sprintf("- %s\n", l.formatClientAppType(clientApp)))
		}
		md.WriteString("\n")
	}

	// Risk Levels
	if len(conditions.SignInRiskLevels) > 0 {
		md.WriteString(fmt.Sprintf("**Sign-in Risk Levels**: %s\n\n", strings.Join(conditions.SignInRiskLevels, ", ")))
	}

	if len(conditions.UserRiskLevels) > 0 {
		md.WriteString(fmt.Sprintf("**User Risk Levels**: %s\n\n", strings.Join(conditions.UserRiskLevels, ", ")))
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) formatGrantControls(md *strings.Builder, grantControls map[string]interface{}) {
	if operator, ok := grantControls["operator"].(string); ok && operator != "" {
		md.WriteString(fmt.Sprintf("**Operator**: %s\n\n", operator))
	}

	if builtInControls, ok := grantControls["builtInControls"].([]interface{}); ok && len(builtInControls) > 0 {
		md.WriteString("**Built-in Controls:**\n")
		for _, control := range builtInControls {
			if controlStr, ok := control.(string); ok {
				md.WriteString(fmt.Sprintf("- %s\n", l.formatBuiltInControl(controlStr)))
			}
		}
		md.WriteString("\n")
	}

	if termsOfUse, ok := grantControls["termsOfUse"].([]interface{}); ok && len(termsOfUse) > 0 {
		md.WriteString("**Terms of Use:**\n")
		for _, term := range termsOfUse {
			if termStr, ok := term.(string); ok {
				md.WriteString(fmt.Sprintf("- %s\n", termStr))
			}
		}
		md.WriteString("\n")
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) formatSessionControls(md *strings.Builder, sessionControls map[string]interface{}) {
	controlsFound := false

	if appEnforced, ok := sessionControls["applicationEnforcedRestrictions"].(map[string]interface{}); ok {
		if isEnabled, ok := appEnforced["isEnabled"].(bool); ok && isEnabled {
			md.WriteString("- **Application Enforced Restrictions**: Enabled\n")
			controlsFound = true
		}
	}

	if cloudAppSecurity, ok := sessionControls["cloudAppSecurity"].(map[string]interface{}); ok {
		if isEnabled, ok := cloudAppSecurity["isEnabled"].(bool); ok && isEnabled {
			md.WriteString("- **Cloud App Security**: Enabled\n")
			controlsFound = true
		}
	}

	if persistentBrowser, ok := sessionControls["persistentBrowser"].(map[string]interface{}); ok {
		if isEnabled, ok := persistentBrowser["isEnabled"].(bool); ok && isEnabled {
			md.WriteString("- **Persistent Browser Session**: Enabled\n")
			controlsFound = true
		}
	}

	if signInFreq, ok := sessionControls["signInFrequency"].(map[string]interface{}); ok {
		if isEnabled, ok := signInFreq["isEnabled"].(bool); ok && isEnabled {
			md.WriteString("- **Sign-in Frequency Control**: Enabled\n")
			controlsFound = true
		}
	}

	if !controlsFound {
		md.WriteString("- No session controls configured\n")
	}

	md.WriteString("\n")
}

// Helper formatting functions
func (l *AzureConditionalAccessOutputFormatterLink) formatPolicyState(state string) string {
	switch state {
	case "enabled":
		return "Enabled"
	case "disabled":
		return "Disabled"
	case "enabledForReportingButNotEnforced":
		return "Report-only"
	default:
		return strings.Title(state)
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) formatPolicyStateWithIcon(state string) string {
	switch state {
	case "enabled":
		return "✅ **Enabled**"
	case "disabled":
		return "❌ **Disabled**"
	case "enabledForReportingButNotEnforced":
		return "📊 **Report-only**"
	default:
		return fmt.Sprintf("❓ **%s**", strings.Title(state))
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) formatDateTime(dateTimeStr string) string {
	if t, err := time.Parse(time.RFC3339, dateTimeStr); err == nil {
		return t.Format("2006-01-02 15:04:05 UTC")
	}
	return dateTimeStr
}

func (l *AzureConditionalAccessOutputFormatterLink) formatPlatform(platform string) string {
	switch platform {
	case "all":
		return "All devices"
	case "android":
		return "Android"
	case "iOS":
		return "iOS"
	case "windows":
		return "Windows"
	case "windowsPhone":
		return "Windows Phone"
	case "macOS":
		return "macOS"
	default:
		return platform
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) formatClientAppType(clientApp string) string {
	switch clientApp {
	case "all":
		return "All client apps"
	case "browser":
		return "Browser"
	case "mobileAppsAndDesktopClients":
		return "Mobile apps and desktop clients"
	case "exchangeActiveSync":
		return "Exchange ActiveSync clients"
	case "easSupported":
		return "Exchange ActiveSync supported clients"
	case "other":
		return "Other clients"
	default:
		return clientApp
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) formatBuiltInControl(control string) string {
	switch control {
	case "block":
		return "Block access"
	case "mfa":
		return "Require multi-factor authentication"
	case "compliantDevice":
		return "Require device to be marked as compliant"
	case "domainJoinedDevice":
		return "Require domain joined device"
	case "approvedApplication":
		return "Require approved client app"
	case "compliantApplication":
		return "Require app protection policy"
	default:
		return control
	}
}

// getTenantID retrieves the current Azure tenant ID
func (l *AzureConditionalAccessOutputFormatterLink) getTenantID() (string, error) {
	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create Graph client
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create Graph client: %w", err)
	}

	// Get organization information to extract tenant ID
	org, err := graphClient.Organization().Get(l.Context(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to get organization info: %w", err)
	}

	if org == nil || org.GetValue() == nil || len(org.GetValue()) == 0 {
		return "", fmt.Errorf("no organization information found")
	}

	// Get the first organization (there's typically only one)
	firstOrg := org.GetValue()[0]
	if firstOrg.GetId() == nil {
		return "", fmt.Errorf("organization ID is nil")
	}

	return *firstOrg.GetId(), nil
}
