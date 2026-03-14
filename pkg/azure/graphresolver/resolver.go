package graphresolver

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sync"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Resolver enriches conditional access policies by resolving UUIDs to
// human-readable names via Microsoft Graph.
type Resolver struct {
	client  *msgraphsdk.GraphServiceClient
	cache   map[string]output.ResolvedEntity
	cacheMu sync.RWMutex
}

func NewResolver(client *msgraphsdk.GraphServiceClient) *Resolver {
	return &Resolver{
		client: client,
		cache:  make(map[string]output.ResolvedEntity),
	}
}

// Resolve is a pipeline-compatible method that enriches a policy with resolved UUIDs.
func (r *Resolver) Resolve(policy output.AzureConditionalAccessPolicy, out *pipeline.P[output.AzureConditionalAccessPolicy]) error {
	ctx := context.Background()
	enriched := r.enrichPolicy(ctx, policy)
	out.Send(enriched)
	return nil
}

func (r *Resolver) enrichPolicy(ctx context.Context, policy output.AzureConditionalAccessPolicy) output.AzureConditionalAccessPolicy {
	if policy.Conditions == nil {
		return policy
	}

	policy.ResolvedUsers = make(map[string]output.ResolvedEntity)
	policy.ResolvedGroups = make(map[string]output.ResolvedEntity)
	policy.ResolvedApplications = make(map[string]output.ResolvedEntity)
	policy.ResolvedRoles = make(map[string]output.ResolvedEntity)

	var userUUIDs, groupUUIDs, appUUIDs, roleUUIDs []string

	if u := policy.Conditions.Users; u != nil {
		userUUIDs = append(userUUIDs, u.IncludeUsers...)
		userUUIDs = append(userUUIDs, u.ExcludeUsers...)
		groupUUIDs = append(groupUUIDs, u.IncludeGroups...)
		groupUUIDs = append(groupUUIDs, u.ExcludeGroups...)
		roleUUIDs = append(roleUUIDs, u.IncludeRoles...)
		roleUUIDs = append(roleUUIDs, u.ExcludeRoles...)
	}

	if a := policy.Conditions.Applications; a != nil {
		appUUIDs = append(appUUIDs, a.IncludeApplications...)
		appUUIDs = append(appUUIDs, a.ExcludeApplications...)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	resolve := func(uuids []string, entityType string, resolveFn func(context.Context, string) output.ResolvedEntity, target map[string]output.ResolvedEntity) {
		filtered := filterValidUUIDs(uuids)
		if len(filtered) == 0 {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, uuid := range filtered {
				entity := r.cachedResolve(ctx, uuid, entityType, resolveFn)
				mu.Lock()
				target[uuid] = entity
				mu.Unlock()
			}
		}()
	}

	resolve(userUUIDs, "user", r.resolveUser, policy.ResolvedUsers)
	resolve(groupUUIDs, "group", r.resolveGroup, policy.ResolvedGroups)
	resolve(appUUIDs, "application", r.resolveApplication, policy.ResolvedApplications)
	resolve(roleUUIDs, "role", r.resolveRole, policy.ResolvedRoles)

	wg.Wait()
	return policy
}

func (r *Resolver) cachedResolve(ctx context.Context, uuid, entityType string, fn func(context.Context, string) output.ResolvedEntity) output.ResolvedEntity {
	r.cacheMu.RLock()
	if cached, ok := r.cache[uuid]; ok {
		r.cacheMu.RUnlock()
		return cached
	}
	r.cacheMu.RUnlock()

	entity := fn(ctx, uuid)

	r.cacheMu.Lock()
	r.cache[uuid] = entity
	r.cacheMu.Unlock()

	return entity
}

func (r *Resolver) resolveUser(ctx context.Context, uuid string) output.ResolvedEntity {
	user, err := r.client.Users().ByUserId(uuid).Get(ctx, nil)
	if err != nil {
		slog.Debug("failed to resolve user", "uuid", uuid, "error", err)
		return fallbackEntity(uuid, "user")
	}

	entity := output.ResolvedEntity{
		ID:   uuid,
		Type: "user",
	}
	if v := user.GetDisplayName(); v != nil {
		entity.DisplayName = *v
	}
	extra := make(map[string]string)
	if v := user.GetUserPrincipalName(); v != nil {
		extra["userPrincipalName"] = *v
	}
	if v := user.GetMail(); v != nil {
		extra["mail"] = *v
	}
	if len(extra) > 0 {
		entity.ExtraInfo = extra
	}
	return entity
}

func (r *Resolver) resolveGroup(ctx context.Context, uuid string) output.ResolvedEntity {
	group, err := r.client.Groups().ByGroupId(uuid).Get(ctx, nil)
	if err != nil {
		slog.Debug("failed to resolve group", "uuid", uuid, "error", err)
		return fallbackEntity(uuid, "group")
	}

	entity := output.ResolvedEntity{
		ID:   uuid,
		Type: "group",
	}
	if v := group.GetDisplayName(); v != nil {
		entity.DisplayName = *v
	}
	if v := group.GetDescription(); v != nil {
		entity.Description = *v
	}
	extra := make(map[string]string)
	if v := group.GetMail(); v != nil {
		extra["mail"] = *v
	}
	if len(extra) > 0 {
		entity.ExtraInfo = extra
	}
	return entity
}

func (r *Resolver) resolveApplication(ctx context.Context, uuid string) output.ResolvedEntity {
	// Try service principal by appId filter first
	filter := fmt.Sprintf("appId eq '%s'", uuid)
	spList, err := r.client.ServicePrincipals().Get(ctx, &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	})
	if err == nil && spList != nil && spList.GetValue() != nil && len(spList.GetValue()) > 0 {
		sp := spList.GetValue()[0]
		return buildAppEntity(uuid, sp.GetDisplayName(), sp.GetDescription(), sp.GetAppId())
	}

	// Try application by appId filter
	appList, err := r.client.Applications().Get(ctx, &applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	})
	if err == nil && appList != nil && appList.GetValue() != nil && len(appList.GetValue()) > 0 {
		app := appList.GetValue()[0]
		return buildAppEntity(uuid, app.GetDisplayName(), app.GetDescription(), app.GetAppId())
	}

	// Try service principal by object ID
	sp, err := r.client.ServicePrincipals().ByServicePrincipalId(uuid).Get(ctx, nil)
	if err == nil {
		return buildAppEntity(uuid, sp.GetDisplayName(), sp.GetDescription(), sp.GetAppId())
	}

	// Try application by object ID
	app, err := r.client.Applications().ByApplicationId(uuid).Get(ctx, nil)
	if err == nil {
		return buildAppEntity(uuid, app.GetDisplayName(), app.GetDescription(), app.GetAppId())
	}

	slog.Debug("failed to resolve application", "uuid", uuid)
	return fallbackEntity(uuid, "application")
}

func (r *Resolver) resolveRole(ctx context.Context, uuid string) output.ResolvedEntity {
	// Try role template first
	rt, err := r.client.DirectoryRoleTemplates().ByDirectoryRoleTemplateId(uuid).Get(ctx, nil)
	if err == nil {
		entity := output.ResolvedEntity{
			ID:        uuid,
			Type:      "role",
			ExtraInfo: map[string]string{"roleTemplateId": uuid},
		}
		if v := rt.GetDisplayName(); v != nil {
			entity.DisplayName = *v
		}
		if v := rt.GetDescription(); v != nil {
			entity.Description = *v
		}
		return entity
	}

	// Fallback to directory role
	role, err := r.client.DirectoryRoles().ByDirectoryRoleId(uuid).Get(ctx, nil)
	if err == nil {
		entity := output.ResolvedEntity{
			ID:   uuid,
			Type: "role",
		}
		if v := role.GetDisplayName(); v != nil {
			entity.DisplayName = *v
		}
		if v := role.GetDescription(); v != nil {
			entity.Description = *v
		}
		if v := role.GetRoleTemplateId(); v != nil {
			entity.ExtraInfo = map[string]string{"roleTemplateId": *v}
		}
		return entity
	}

	slog.Debug("failed to resolve role", "uuid", uuid)
	return fallbackEntity(uuid, "role")
}

func buildAppEntity(uuid string, displayName, description, appID *string) output.ResolvedEntity {
	entity := output.ResolvedEntity{
		ID:   uuid,
		Type: "application",
	}
	if displayName != nil {
		entity.DisplayName = *displayName
	}
	if description != nil {
		entity.Description = *description
	}
	if appID != nil {
		entity.ExtraInfo = map[string]string{"appId": *appID}
	}
	return entity
}

func fallbackEntity(uuid, entityType string) output.ResolvedEntity {
	return output.ResolvedEntity{
		ID:          uuid,
		Type:        entityType,
		DisplayName: fmt.Sprintf("Unknown %s (%s)", entityType, uuid[:min(8, len(uuid))]),
	}
}

func filterValidUUIDs(uuids []string) []string {
	seen := make(map[string]struct{}, len(uuids))
	filtered := make([]string, 0, len(uuids))
	for _, uuid := range uuids {
		if uuid == "All" || uuid == "None" || uuid == "GuestsOrExternalUsers" || uuid == "" {
			continue
		}
		if _, dup := seen[uuid]; dup {
			continue
		}
		if uuidRegex.MatchString(uuid) {
			seen[uuid] = struct{}{}
			filtered = append(filtered, uuid)
		}
	}
	return filtered
}
