package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AzureConditionalAccessPoliciesModule{})
}

// AzureConditionalAccessPoliciesModule retrieves and documents Azure Conditional Access policies
// with human-readable formatting, resolving UUIDs to names for users, groups, and applications
type AzureConditionalAccessPoliciesModule struct{}

// Metadata methods

func (m *AzureConditionalAccessPoliciesModule) ID() string {
	return "conditional-access-policies"
}

func (m *AzureConditionalAccessPoliciesModule) Name() string {
	return "Conditional Access Policies"
}

func (m *AzureConditionalAccessPoliciesModule) Description() string {
	return "Retrieve and document Azure Conditional Access policies with human-readable formatting, resolving UUIDs to names for users, groups, and applications. Optionally analyze policies using LLM."
}

func (m *AzureConditionalAccessPoliciesModule) Platform() plugin.Platform {
	return plugin.PlatformAzure
}

func (m *AzureConditionalAccessPoliciesModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *AzureConditionalAccessPoliciesModule) OpsecLevel() string {
	return "stealth"
}

func (m *AzureConditionalAccessPoliciesModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AzureConditionalAccessPoliciesModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies",
		"https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy",
		"https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers",
		"https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications",
	}
}

// Parameters defines the module parameters
func (m *AzureConditionalAccessPoliciesModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "module-name",
			Description: "Name of the module for dynamic file naming",
			Type:        "string",
			Required:    false,
			Default:     "conditional-access-policies",
		},
		{
			Name:        "enable-llm-analysis",
			Description: "Enable LLM analysis of conditional access policies",
			Type:        "bool",
			Required:    false,
			Default:     false,
		},
		{
			Name:        "llm-api-key",
			Description: "API key for LLM provider (optional, uses environment variable if not provided)",
			Type:        "string",
			Required:    false,
		},
		{
			Name:        "llm-provider",
			Description: "LLM provider to use (openai, anthropic, etc.)",
			Type:        "string",
			Required:    false,
			Default:     "openai",
		},
		{
			Name:        "llm-model",
			Description: "LLM model to use for analysis",
			Type:        "string",
			Required:    false,
			Default:     "gpt-4",
		},
	}
}

// ConditionalAccessPolicyResult represents a collected policy
type ConditionalAccessPolicyResult struct {
	ID               string                        `json:"id"`
	DisplayName      string                        `json:"displayName"`
	State            string                        `json:"state"`
	TemplateID       *string                       `json:"templateId,omitempty"`
	CreatedDateTime  string                        `json:"createdDateTime"`
	ModifiedDateTime string                        `json:"modifiedDateTime"`
	Conditions       *ConditionalAccessConditionSet `json:"conditions,omitempty"`
	GrantControls    map[string]interface{}        `json:"grantControls,omitempty"`
	SessionControls  map[string]interface{}        `json:"sessionControls,omitempty"`
}

// ConditionalAccessConditionSet represents policy conditions
type ConditionalAccessConditionSet struct {
	Users            *ConditionalAccessUsers        `json:"users,omitempty"`
	Applications     *ConditionalAccessApplications `json:"applications,omitempty"`
	Locations        map[string]interface{}         `json:"locations,omitempty"`
	Platforms        map[string]interface{}         `json:"platforms,omitempty"`
	ClientAppTypes   []string                       `json:"clientAppTypes,omitempty"`
	SignInRiskLevels []string                       `json:"signInRiskLevels,omitempty"`
	UserRiskLevels   []string                       `json:"userRiskLevels,omitempty"`
	DeviceStates     map[string]interface{}         `json:"deviceStates,omitempty"`
}

// ConditionalAccessUsers represents user conditions
type ConditionalAccessUsers struct {
	IncludeUsers                 []string               `json:"includeUsers,omitempty"`
	ExcludeUsers                 []string               `json:"excludeUsers,omitempty"`
	IncludeGroups                []string               `json:"includeGroups,omitempty"`
	ExcludeGroups                []string               `json:"excludeGroups,omitempty"`
	IncludeRoles                 []string               `json:"includeRoles,omitempty"`
	ExcludeRoles                 []string               `json:"excludeRoles,omitempty"`
	IncludeGuestsOrExternalUsers map[string]interface{} `json:"includeGuestsOrExternalUsers,omitempty"`
	ExcludeGuestsOrExternalUsers map[string]interface{} `json:"excludeGuestsOrExternalUsers,omitempty"`
}

// ConditionalAccessApplications represents application conditions
type ConditionalAccessApplications struct {
	IncludeApplications []string               `json:"includeApplications,omitempty"`
	ExcludeApplications []string               `json:"excludeApplications,omitempty"`
	IncludeUserActions  []string               `json:"includeUserActions,omitempty"`
	ApplicationFilter   map[string]interface{} `json:"applicationFilter,omitempty"`
}

// EnrichedConditionalAccessPolicy represents a policy with resolved names
type EnrichedConditionalAccessPolicy struct {
	ConditionalAccessPolicyResult
	ResolvedData map[string]interface{} `json:"resolvedData,omitempty"`
}

// Run executes the Conditional Access Policies module
func (m *AzureConditionalAccessPoliciesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	slog.Info("Starting Azure Conditional Access Policy collection")

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create Graph client
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Graph client: %w", err)
	}

	// Step 1: Collect conditional access policies
	policies, err := m.getConditionalAccessPolicies(ctx, graphClient)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve conditional access policies: %w", err)
	}

	slog.Info("Successfully collected conditional access policies", "count", len(policies))

	// Step 2: Resolve UUIDs to human-readable names
	enrichedPolicies, err := m.resolveUUIDs(ctx, graphClient, policies)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UUIDs: %w", err)
	}

	// Step 3: Format output
	formattedOutput := m.formatOutput(enrichedPolicies)

	// Step 4: Optionally perform LLM analysis
	var analysisResult map[string]interface{}
	enableLLM, _ := cfg.Args["enable-llm-analysis"].(bool)
	if enableLLM {
		analysisResult, err = m.performLLMAnalysis(ctx, cfg, enrichedPolicies)
		if err != nil {
			slog.Warn("LLM analysis failed", "error", err)
		}
	}

	// Step 5: Aggregate results
	output := m.createCombinedOutput(enrichedPolicies, analysisResult)

	return []plugin.Result{
		{
			Data:     output,
			Metadata: formattedOutput,
		},
	}, nil
}

// getConditionalAccessPolicies retrieves all conditional access policies
func (m *AzureConditionalAccessPoliciesModule) getConditionalAccessPolicies(ctx context.Context, graphClient *msgraphsdk.GraphServiceClient) ([]ConditionalAccessPolicyResult, error) {
	var allPolicies []ConditionalAccessPolicyResult

	// Retrieve conditional access policies using the Graph SDK
	result, err := graphClient.Identity().ConditionalAccess().Policies().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve policies: %w", err)
	}

	// Process the initial batch
	policies := result.GetValue()
	for _, policy := range policies {
		policyResult := m.convertToResult(policy)
		allPolicies = append(allPolicies, policyResult)
	}

	// Handle pagination
	pageIterator, err := msgraphcore.NewPageIterator[models.ConditionalAccessPolicyable](
		result,
		graphClient.GetAdapter(),
		models.CreateConditionalAccessPolicyCollectionResponseFromDiscriminatorValue,
	)
	if err != nil {
		return allPolicies, nil // Return what we have so far
	}

	err = pageIterator.Iterate(ctx, func(policy models.ConditionalAccessPolicyable) bool {
		policyResult := m.convertToResult(policy)
		allPolicies = append(allPolicies, policyResult)
		return true
	})

	if err != nil {
		slog.Warn("Error during pagination", "error", err)
	}

	return allPolicies, nil
}

// convertToResult converts Graph SDK model to internal result type
func (m *AzureConditionalAccessPoliciesModule) convertToResult(policy models.ConditionalAccessPolicyable) ConditionalAccessPolicyResult {
	state := ""
	if s := policy.GetState(); s != nil {
		state = (*s).String()
	}
	result := ConditionalAccessPolicyResult{
		ID:               derefString(policy.GetId()),
		DisplayName:      derefString(policy.GetDisplayName()),
		State:            state,
		CreatedDateTime:  derefTime(policy.GetCreatedDateTime()).Format(time.RFC3339),
		ModifiedDateTime: derefTime(policy.GetModifiedDateTime()).Format(time.RFC3339),
	}

	if templateID := policy.GetTemplateId(); templateID != nil {
		result.TemplateID = templateID
	}

	// Convert conditions
	if conditions := policy.GetConditions(); conditions != nil {
		result.Conditions = m.convertConditions(conditions)
	}

	// Convert grant controls
	if grantControls := policy.GetGrantControls(); grantControls != nil {
		result.GrantControls = m.convertToMap(grantControls)
	}

	// Convert session controls
	if sessionControls := policy.GetSessionControls(); sessionControls != nil {
		result.SessionControls = m.convertToMap(sessionControls)
	}

	return result
}

// convertConditions converts Graph SDK conditions to internal type
func (m *AzureConditionalAccessPoliciesModule) convertConditions(conditions models.ConditionalAccessConditionSetable) *ConditionalAccessConditionSet {
	result := &ConditionalAccessConditionSet{}

	if users := conditions.GetUsers(); users != nil {
		result.Users = &ConditionalAccessUsers{
			IncludeUsers:  users.GetIncludeUsers(),
			ExcludeUsers:  users.GetExcludeUsers(),
			IncludeGroups: users.GetIncludeGroups(),
			ExcludeGroups: users.GetExcludeGroups(),
			IncludeRoles:  users.GetIncludeRoles(),
			ExcludeRoles:  users.GetExcludeRoles(),
		}
	}

	if apps := conditions.GetApplications(); apps != nil {
		result.Applications = &ConditionalAccessApplications{
			IncludeApplications: apps.GetIncludeApplications(),
			ExcludeApplications: apps.GetExcludeApplications(),
			IncludeUserActions:  apps.GetIncludeUserActions(),
		}
	}

	if clientAppTypes := conditions.GetClientAppTypes(); clientAppTypes != nil {
		result.ClientAppTypes = make([]string, len(clientAppTypes))
		for i, t := range clientAppTypes {
			result.ClientAppTypes[i] = t.String()
		}
	}

	return result
}

// resolveUUIDs resolves user, group, and application UUIDs to names
func (m *AzureConditionalAccessPoliciesModule) resolveUUIDs(ctx context.Context, graphClient *msgraphsdk.GraphServiceClient, policies []ConditionalAccessPolicyResult) ([]EnrichedConditionalAccessPolicy, error) {
	enrichedPolicies := make([]EnrichedConditionalAccessPolicy, len(policies))

	// Build sets of UUIDs to resolve
	userIDs := make(map[string]bool)
	groupIDs := make(map[string]bool)
	appIDs := make(map[string]bool)

	for _, policy := range policies {
		if policy.Conditions != nil {
			if users := policy.Conditions.Users; users != nil {
				for _, id := range users.IncludeUsers {
					userIDs[id] = true
				}
				for _, id := range users.ExcludeUsers {
					userIDs[id] = true
				}
				for _, id := range users.IncludeGroups {
					groupIDs[id] = true
				}
				for _, id := range users.ExcludeGroups {
					groupIDs[id] = true
				}
			}
			if apps := policy.Conditions.Applications; apps != nil {
				for _, id := range apps.IncludeApplications {
					appIDs[id] = true
				}
				for _, id := range apps.ExcludeApplications {
					appIDs[id] = true
				}
			}
		}
	}

	// Resolve UUIDs (batch lookups)
	userNames := m.resolveUsers(ctx, graphClient, userIDs)
	groupNames := m.resolveGroups(ctx, graphClient, groupIDs)
	appNames := m.resolveApplications(ctx, graphClient, appIDs)

	// Enrich policies with resolved names
	for i, policy := range policies {
		enrichedPolicies[i] = EnrichedConditionalAccessPolicy{
			ConditionalAccessPolicyResult: policy,
			ResolvedData: map[string]interface{}{
				"users":        userNames,
				"groups":       groupNames,
				"applications": appNames,
			},
		}
	}

	return enrichedPolicies, nil
}

// resolveUsers resolves user UUIDs to display names
func (m *AzureConditionalAccessPoliciesModule) resolveUsers(ctx context.Context, graphClient *msgraphsdk.GraphServiceClient, userIDs map[string]bool) map[string]string {
	resolved := make(map[string]string)
	for id := range userIDs {
		if id == "All" || id == "GuestsOrExternalUsers" {
			resolved[id] = id
			continue
		}
		user, err := graphClient.Users().ByUserId(id).Get(ctx, nil)
		if err != nil {
			resolved[id] = id // Keep UUID on error
			continue
		}
		resolved[id] = derefString(user.GetDisplayName())
	}
	return resolved
}

// resolveGroups resolves group UUIDs to display names
func (m *AzureConditionalAccessPoliciesModule) resolveGroups(ctx context.Context, graphClient *msgraphsdk.GraphServiceClient, groupIDs map[string]bool) map[string]string {
	resolved := make(map[string]string)
	for id := range groupIDs {
		group, err := graphClient.Groups().ByGroupId(id).Get(ctx, nil)
		if err != nil {
			resolved[id] = id
			continue
		}
		resolved[id] = derefString(group.GetDisplayName())
	}
	return resolved
}

// resolveApplications resolves application UUIDs to display names
func (m *AzureConditionalAccessPoliciesModule) resolveApplications(ctx context.Context, graphClient *msgraphsdk.GraphServiceClient, appIDs map[string]bool) map[string]string {
	resolved := make(map[string]string)
	for id := range appIDs {
		if id == "All" || id == "Office365" {
			resolved[id] = id
			continue
		}
		app, err := graphClient.Applications().ByApplicationId(id).Get(ctx, nil)
		if err != nil {
			// Try service principals
			sp, err := graphClient.ServicePrincipals().ByServicePrincipalId(id).Get(ctx, nil)
			if err != nil {
				resolved[id] = id
				continue
			}
			resolved[id] = derefString(sp.GetDisplayName())
			continue
		}
		resolved[id] = derefString(app.GetDisplayName())
	}
	return resolved
}

// formatOutput formats the enriched policies for human-readable output
func (m *AzureConditionalAccessPoliciesModule) formatOutput(policies []EnrichedConditionalAccessPolicy) map[string]interface{} {
	return map[string]interface{}{
		"policies": policies,
		"metadata": map[string]interface{}{
			"total_count":     len(policies),
			"collection_time": time.Now().Format(time.RFC3339),
		},
	}
}

// performLLMAnalysis performs optional LLM analysis on policies
func (m *AzureConditionalAccessPoliciesModule) performLLMAnalysis(ctx context.Context, cfg plugin.Config, policies []EnrichedConditionalAccessPolicy) (map[string]interface{}, error) {
	// TODO: Implement LLM analysis using the provided API key and model
	// This consolidates azure.NewAzureConditionalAccessLLMAnalyzer
	slog.Info("LLM analysis requested but not yet implemented")
	return map[string]interface{}{
		"status":  "not_implemented",
		"message": "LLM analysis feature pending implementation",
	}, nil
}

// createCombinedOutput aggregates recon data and optional LLM analysis
func (m *AzureConditionalAccessPoliciesModule) createCombinedOutput(policies []EnrichedConditionalAccessPolicy, analysis map[string]interface{}) map[string]interface{} {
	output := map[string]interface{}{
		"collection_time": time.Now().Format(time.RFC3339),
		"data_type":       "azure_conditional_access_comprehensive",
		"policies_count":  len(policies),
		"policies":        policies,
	}

	if analysis != nil {
		output["llm_analysis"] = analysis
		output["llm_enabled"] = true
	} else {
		output["llm_enabled"] = false
	}

	return output
}

// Helper functions

func (m *AzureConditionalAccessPoliciesModule) convertToMap(obj interface{}) map[string]interface{} {
	data, _ := json.Marshal(obj)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}


func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
