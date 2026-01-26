package gcloudiam

import (
	"fmt"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
)

type RoleExpander struct {
	rolePermsByName map[string]gcptypes.PermissionSet
}

func NewRoleExpander() *RoleExpander {
	return &RoleExpander{
		rolePermsByName: make(map[string]gcptypes.PermissionSet),
	}
}

func (re *RoleExpander) AddRole(role *gcptypes.Role) {
	permSet := gcptypes.NewPermissionSet()
	for _, p := range role.IncludedPermissions {
		permSet.Add(p)
	}
	if len(permSet) > 0 {
		re.rolePermsByName[role.Name] = permSet
	}
}

func (re *RoleExpander) AddRoles(roles []*gcptypes.Role) {
	for _, role := range roles {
		re.AddRole(role)
	}
}

func (re *RoleExpander) ExpandRole(roleName string) (gcptypes.PermissionSet, error) {
	if perms, ok := re.rolePermsByName[roleName]; ok {
		return perms, nil
	}
	return nil, fmt.Errorf("role not found: %s", roleName)
}

func (re *RoleExpander) HasRole(roleName string) bool {
	_, ok := re.rolePermsByName[roleName]
	return ok
}
