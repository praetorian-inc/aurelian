package azure

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

type AzureConditionalAccessResolverLink struct {
	*chain.Base
}

func NewAzureConditionalAccessResolverLink(configs ...cfg.Config) chain.Link {
	l := &AzureConditionalAccessResolverLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureConditionalAccessResolverLink) Params() []cfg.Param {
	return []cfg.Param{}
}

// ResolvedEntity represents a resolved UUID with its human-readable information
type ResolvedEntity struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"` // "user", "group", "application", "role"
	DisplayName  string            `json:"displayName"`
	Description  string            `json:"description,omitempty"`
	ExtraInfo    map[string]string `json:"extraInfo,omitempty"`
}

// EnrichedConditionalAccessPolicy contains the original policy data with resolved UUIDs
type EnrichedConditionalAccessPolicy struct {
	ConditionalAccessPolicyResult
	ResolvedUsers        map[string]ResolvedEntity `json:"resolvedUsers,omitempty"`
	ResolvedGroups       map[string]ResolvedEntity `json:"resolvedGroups,omitempty"`
	ResolvedApplications map[string]ResolvedEntity `json:"resolvedApplications,omitempty"`
	ResolvedRoles        map[string]ResolvedEntity `json:"resolvedRoles,omitempty"`
}

func (l *AzureConditionalAccessResolverLink) Process(input any) error {
	slog.Info("Starting UUID resolution for Conditional Access Policies")

	// Expect input to be []ConditionalAccessPolicyResult from collector
	policies, ok := input.([]ConditionalAccessPolicyResult)
	if !ok {
		return fmt.Errorf("expected []ConditionalAccessPolicyResult, got %T", input)
	}

	// Get Azure credentials and create Graph client
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Graph client: %w", err)
	}

	// Create UUID resolver
	resolver := NewUUIDResolver(graphClient)

	// Process each policy to resolve UUIDs
	var enrichedPolicies []EnrichedConditionalAccessPolicy
	
	for _, policy := range policies {
		enrichedPolicy, err := l.enrichPolicyWithResolvedUUIDs(l.Context(), resolver, policy)
		if err != nil {
			slog.Warn("Failed to enrich policy with resolved UUIDs", "policy_id", policy.ID, "error", err)
			// Continue with other policies even if one fails
			enrichedPolicies = append(enrichedPolicies, EnrichedConditionalAccessPolicy{
				ConditionalAccessPolicyResult: policy,
			})
			continue
		}
		
		enrichedPolicies = append(enrichedPolicies, enrichedPolicy)
	}

	slog.Info("Successfully resolved UUIDs for conditional access policies", "count", len(enrichedPolicies))

	// Pass enriched data to output formatter
	return l.Send(enrichedPolicies)
}

func (l *AzureConditionalAccessResolverLink) enrichPolicyWithResolvedUUIDs(ctx context.Context, resolver *UUIDResolver, policy ConditionalAccessPolicyResult) (EnrichedConditionalAccessPolicy, error) {
	enriched := EnrichedConditionalAccessPolicy{
		ConditionalAccessPolicyResult: policy,
		ResolvedUsers:                 make(map[string]ResolvedEntity),
		ResolvedGroups:                make(map[string]ResolvedEntity),
		ResolvedApplications:          make(map[string]ResolvedEntity),
		ResolvedRoles:                 make(map[string]ResolvedEntity),
	}

	if policy.Conditions == nil {
		return enriched, nil
	}

	// Collect all UUIDs that need resolution
	var userUUIDs, groupUUIDs, appUUIDs, roleUUIDs []string

	if policy.Conditions.Users != nil {
		userUUIDs = append(userUUIDs, policy.Conditions.Users.IncludeUsers...)
		userUUIDs = append(userUUIDs, policy.Conditions.Users.ExcludeUsers...)
		groupUUIDs = append(groupUUIDs, policy.Conditions.Users.IncludeGroups...)
		groupUUIDs = append(groupUUIDs, policy.Conditions.Users.ExcludeGroups...)
		roleUUIDs = append(roleUUIDs, policy.Conditions.Users.IncludeRoles...)
		roleUUIDs = append(roleUUIDs, policy.Conditions.Users.ExcludeRoles...)
	}

	if policy.Conditions.Applications != nil {
		appUUIDs = append(appUUIDs, policy.Conditions.Applications.IncludeApplications...)
		appUUIDs = append(appUUIDs, policy.Conditions.Applications.ExcludeApplications...)
	}

	// Resolve UUIDs in parallel for efficiency
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Resolve users
	if len(userUUIDs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolved, err := resolver.ResolveUsers(ctx, l.filterValidUUIDs(userUUIDs))
			if err != nil {
				slog.Warn("Failed to resolve user UUIDs", "error", err)
				return
			}
			mu.Lock()
			for uuid, entity := range resolved {
				enriched.ResolvedUsers[uuid] = entity
			}
			mu.Unlock()
		}()
	}

	// Resolve groups
	if len(groupUUIDs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolved, err := resolver.ResolveGroups(ctx, l.filterValidUUIDs(groupUUIDs))
			if err != nil {
				slog.Warn("Failed to resolve group UUIDs", "error", err)
				return
			}
			mu.Lock()
			for uuid, entity := range resolved {
				enriched.ResolvedGroups[uuid] = entity
			}
			mu.Unlock()
		}()
	}

	// Resolve applications
	if len(appUUIDs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolved, err := resolver.ResolveApplications(ctx, l.filterValidUUIDs(appUUIDs))
			if err != nil {
				slog.Warn("Failed to resolve application UUIDs", "error", err)
				return
			}
			mu.Lock()
			for uuid, entity := range resolved {
				enriched.ResolvedApplications[uuid] = entity
			}
			mu.Unlock()
		}()
	}

	// Resolve roles
	if len(roleUUIDs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolved, err := resolver.ResolveDirectoryRoles(ctx, l.filterValidUUIDs(roleUUIDs))
			if err != nil {
				slog.Warn("Failed to resolve role UUIDs", "error", err)
				return
			}
			mu.Lock()
			for uuid, entity := range resolved {
				enriched.ResolvedRoles[uuid] = entity
			}
			mu.Unlock()
		}()
	}

	// Wait for all resolution to complete
	wg.Wait()

	return enriched, nil
}

// filterValidUUIDs removes common non-UUID values like "All", "None", "GuestsOrExternalUsers"
func (l *AzureConditionalAccessResolverLink) filterValidUUIDs(uuids []string) []string {
	var filtered []string
	for _, uuid := range uuids {
		// Skip common non-UUID values
		if uuid == "All" || uuid == "None" || uuid == "GuestsOrExternalUsers" || uuid == "" {
			continue
		}
		// Basic UUID format check (36 characters with dashes)
		if len(uuid) == 36 && uuid[8] == '-' && uuid[13] == '-' {
			filtered = append(filtered, uuid)
		}
	}
	return filtered
}

// UUIDResolver handles batch resolution of UUIDs to human-readable names
type UUIDResolver struct {
	graphClient *msgraphsdk.GraphServiceClient
	cache       map[string]ResolvedEntity
	cacheMu     sync.RWMutex
}

func NewUUIDResolver(graphClient *msgraphsdk.GraphServiceClient) *UUIDResolver {
	return &UUIDResolver{
		graphClient: graphClient,
		cache:       make(map[string]ResolvedEntity),
	}
}

func (r *UUIDResolver) ResolveUsers(ctx context.Context, userUUIDs []string) (map[string]ResolvedEntity, error) {
	return r.resolveEntities(ctx, userUUIDs, "user", func(ctx context.Context, uuid string) (ResolvedEntity, error) {
		user, err := r.graphClient.Users().ByUserId(uuid).Get(ctx, nil)
		if err != nil {
			return ResolvedEntity{}, fmt.Errorf("failed to get user %s: %w", uuid, err)
		}

		entity := ResolvedEntity{
			ID:   uuid,
			Type: "user",
		}

		if displayName := user.GetDisplayName(); displayName != nil {
			entity.DisplayName = *displayName
		}

		if upn := user.GetUserPrincipalName(); upn != nil {
			if entity.ExtraInfo == nil {
				entity.ExtraInfo = make(map[string]string)
			}
			entity.ExtraInfo["userPrincipalName"] = *upn
		}

		if mail := user.GetMail(); mail != nil {
			if entity.ExtraInfo == nil {
				entity.ExtraInfo = make(map[string]string)
			}
			entity.ExtraInfo["mail"] = *mail
		}

		return entity, nil
	})
}

func (r *UUIDResolver) ResolveGroups(ctx context.Context, groupUUIDs []string) (map[string]ResolvedEntity, error) {
	return r.resolveEntities(ctx, groupUUIDs, "group", func(ctx context.Context, uuid string) (ResolvedEntity, error) {
		group, err := r.graphClient.Groups().ByGroupId(uuid).Get(ctx, nil)
		if err != nil {
			return ResolvedEntity{}, fmt.Errorf("failed to get group %s: %w", uuid, err)
		}

		entity := ResolvedEntity{
			ID:   uuid,
			Type: "group",
		}

		if displayName := group.GetDisplayName(); displayName != nil {
			entity.DisplayName = *displayName
		}

		if description := group.GetDescription(); description != nil {
			entity.Description = *description
		}

		if mail := group.GetMail(); mail != nil {
			if entity.ExtraInfo == nil {
				entity.ExtraInfo = make(map[string]string)
			}
			entity.ExtraInfo["mail"] = *mail
		}

		return entity, nil
	})
}

func (r *UUIDResolver) ResolveApplications(ctx context.Context, appUUIDs []string) (map[string]ResolvedEntity, error) {
	return r.resolveEntities(ctx, appUUIDs, "application", func(ctx context.Context, uuid string) (ResolvedEntity, error) {
		// Try service principals first (more common in conditional access)
		servicePrincipal, err := r.graphClient.ServicePrincipals().ByServicePrincipalId(uuid).Get(ctx, nil)
		if err == nil {
			entity := ResolvedEntity{
				ID:   uuid,
				Type: "application",
			}

			if displayName := servicePrincipal.GetDisplayName(); displayName != nil {
				entity.DisplayName = *displayName
			}

			if description := servicePrincipal.GetDescription(); description != nil {
				entity.Description = *description
			}

			if appId := servicePrincipal.GetAppId(); appId != nil {
				if entity.ExtraInfo == nil {
					entity.ExtraInfo = make(map[string]string)
				}
				entity.ExtraInfo["appId"] = *appId
			}

			return entity, nil
		}

		// Fallback to applications
		app, err := r.graphClient.Applications().ByApplicationId(uuid).Get(ctx, nil)
		if err != nil {
			return ResolvedEntity{}, fmt.Errorf("failed to get application %s: %w", uuid, err)
		}

		entity := ResolvedEntity{
			ID:   uuid,
			Type: "application",
		}

		if displayName := app.GetDisplayName(); displayName != nil {
			entity.DisplayName = *displayName
		}

		if description := app.GetDescription(); description != nil {
			entity.Description = *description
		}

		if appId := app.GetAppId(); appId != nil {
			if entity.ExtraInfo == nil {
				entity.ExtraInfo = make(map[string]string)
			}
			entity.ExtraInfo["appId"] = *appId
		}

		return entity, nil
	})
}

func (r *UUIDResolver) ResolveDirectoryRoles(ctx context.Context, roleUUIDs []string) (map[string]ResolvedEntity, error) {
	return r.resolveEntities(ctx, roleUUIDs, "role", func(ctx context.Context, uuid string) (ResolvedEntity, error) {
		role, err := r.graphClient.DirectoryRoles().ByDirectoryRoleId(uuid).Get(ctx, nil)
		if err != nil {
			return ResolvedEntity{}, fmt.Errorf("failed to get directory role %s: %w", uuid, err)
		}

		entity := ResolvedEntity{
			ID:   uuid,
			Type: "role",
		}

		if displayName := role.GetDisplayName(); displayName != nil {
			entity.DisplayName = *displayName
		}

		if description := role.GetDescription(); description != nil {
			entity.Description = *description
		}

		if roleTemplateId := role.GetRoleTemplateId(); roleTemplateId != nil {
			if entity.ExtraInfo == nil {
				entity.ExtraInfo = make(map[string]string)
			}
			entity.ExtraInfo["roleTemplateId"] = *roleTemplateId
		}

		return entity, nil
	})
}

// resolveEntities is a generic function to resolve UUIDs with caching
func (r *UUIDResolver) resolveEntities(ctx context.Context, uuids []string, entityType string, resolver func(context.Context, string) (ResolvedEntity, error)) (map[string]ResolvedEntity, error) {
	result := make(map[string]ResolvedEntity)
	var toResolve []string

	// Check cache first
	r.cacheMu.RLock()
	for _, uuid := range uuids {
		if cached, exists := r.cache[uuid]; exists {
			result[uuid] = cached
		} else {
			toResolve = append(toResolve, uuid)
		}
	}
	r.cacheMu.RUnlock()

	// Resolve uncached UUIDs
	for _, uuid := range toResolve {
		entity, err := resolver(ctx, uuid)
		if err != nil {
			slog.Warn("Failed to resolve UUID", "uuid", uuid, "type", entityType, "error", err)
			// Create a fallback entity with just the UUID
			entity = ResolvedEntity{
				ID:          uuid,
				Type:        entityType,
				DisplayName: fmt.Sprintf("Unknown %s (%s)", entityType, uuid[:8]),
			}
		}

		result[uuid] = entity

		// Cache the result
		r.cacheMu.Lock()
		r.cache[uuid] = entity
		r.cacheMu.Unlock()
	}

	return result, nil
}