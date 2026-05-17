package iam

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"google.golang.org/api/option"

	iamv1 "google.golang.org/api/iam/v1"
)

// RoleExpander fetches all predefined GCP IAM roles and their permissions,
// caching the result for subsequent calls. It follows the same lazy-loading
// pattern as the AWS ActionExpander.
type RoleExpander struct {
	rolePermissions map[string][]string
	once            sync.Once
	initErr         error
	clientOptions   []option.ClientOption
}

// SetClientOptions configures the client options used when creating the IAM
// service. Must be called before the first Expand call.
func (re *RoleExpander) SetClientOptions(opts ...option.ClientOption) {
	re.clientOptions = opts
}

// ExpandRoles takes a list of GCP IAM role names (e.g. "roles/editor",
// "roles/storage.admin") and returns the deduplicated, sorted union of all
// their permissions. On first call the full set of predefined roles is fetched
// from the IAM API and cached.
func ExpandRoles(ctx context.Context, roles []string, clientOptions ...option.ClientOption) ([]string, error) {
	re := &RoleExpander{clientOptions: clientOptions}
	return re.Expand(ctx, roles)
}

// Expand resolves the given role names to the union of their permissions.
func (re *RoleExpander) Expand(ctx context.Context, roles []string) ([]string, error) {
	re.once.Do(func() {
		re.rolePermissions, re.initErr = re.fetchAllRoles(ctx)
		if re.initErr != nil {
			slog.Error("Error fetching GCP IAM roles during initialization", "error", re.initErr)
		} else {
			slog.Debug("Successfully loaded GCP IAM roles", "count", len(re.rolePermissions))
		}
	})
	if re.initErr != nil {
		return nil, re.initErr
	}

	seen := make(map[string]struct{})
	for _, role := range roles {
		perms, ok := re.rolePermissions[role]
		if !ok {
			slog.Warn("GCP IAM role not found in predefined roles", "role", role)
			continue
		}
		for _, p := range perms {
			seen[p] = struct{}{}
		}
	}

	result := make([]string, 0, len(seen))
	for p := range seen {
		result = append(result, p)
	}
	sort.Strings(result)

	slog.Debug("Expanded GCP IAM roles", "roles", len(roles), "permissions", len(result))
	return result, nil
}

func (re *RoleExpander) fetchAllRoles(ctx context.Context) (map[string][]string, error) {
	svc, err := iamv1.NewService(ctx, re.clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating IAM service: %w", err)
	}

	rolePerms := make(map[string][]string)
	err = svc.Roles.List().
		PageSize(1000).
		View("FULL").
		Pages(ctx, func(resp *iamv1.ListRolesResponse) error {
			for _, role := range resp.Roles {
				rolePerms[role.Name] = role.IncludedPermissions
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("listing IAM roles: %w", err)
	}

	return rolePerms, nil
}
