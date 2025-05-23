package aws

import (
	"encoding/json"
	"sort"
	"sync"
)

// PermissionsSummary maps principal ARNs to their permissions
type PermissionsSummary struct {
	Permissions sync.Map // Key is principal ARN, value is *PrincipalPermissions
	mu          sync.RWMutex
}

// NewPermissionsSummary creates a new empty PermissionsSummary
func NewPermissionsSummary() *PermissionsSummary {
	return &PermissionsSummary{
		Permissions: sync.Map{},
	}
}

// AddPermission safely adds or updates a permission for a principal
func (ps *PermissionsSummary) AddPermission(principalArn, resourceArn, action string, allowed bool, eval *EvaluationResult) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Get or create principal permissions
	val, _ := ps.Permissions.LoadOrStore(principalArn, NewPrincipalPermissions(principalArn))
	perms := val.(*PrincipalPermissions)

	// Add the resource permission
	perms.AddResourcePermission(resourceArn, action, allowed, eval)
}

// GetPrincipals returns a sorted list of all principal ARNs
func (ps *PermissionsSummary) GetPrincipals() []string {
	principals := make([]string, 0)
	ps.Permissions.Range(func(key, value interface{}) bool {
		principals = append(principals, key.(string))
		return true
	})
	sort.Strings(principals)
	return principals
}

// MarshalJSON implements custom JSON marshaling
func (ps *PermissionsSummary) MarshalJSON() ([]byte, error) {
	// Convert sync.Map to regular map for marshaling
	permissions := make(map[string]*PrincipalPermissions)
	ps.Permissions.Range(func(key, value interface{}) bool {
		permissions[key.(string)] = value.(*PrincipalPermissions)
		return true
	})

	return json.Marshal(struct {
		Permissions map[string]*PrincipalPermissions `json:"permissions"`
	}{
		Permissions: permissions,
	})
}

// GetResults returns analyzed permissions for each principal, excluding resources with no actions
func (ps *PermissionsSummary) GetResults() []PrincipalResult {
	results := make([]PrincipalResult, 0)

	ps.Permissions.Range(func(key, value interface{}) bool {
		if perms, ok := value.(*PrincipalPermissions); ok {
			result := PrincipalResult{
				PrincipalArn:  perms.PrincipalArn,
				ResourcePerms: make(map[string][]string),
			}

			// Convert ResourcePerms sync.Map to map, skipping empty resources
			perms.ResourcePerms.Range(func(resKey, resValue interface{}) bool {
				if resPerm, ok := resValue.(*ResourcePermission); ok {
					// Only include resources that have allowed or denied actions
					if len(resPerm.AllowedActions) > 0 {
						resArn := resKey.(string)
						actions := make([]string, 0)

						// Add allowed actions
						if len(resPerm.AllowedActions) > 0 {
							for _, action := range resPerm.AllowedActions {
								actions = append(actions, action.Name)
							}
						}

						// Only add if we have actions
						if len(actions) > 0 {
							result.ResourcePerms[resArn] = actions
						}
					}
				}
				return true
			})

			// Only add principals that have at least one resource with actions
			if len(result.ResourcePerms) > 0 {
				results = append(results, result)
			}
		}
		return true
	})

	// Sort by principal ARN for consistent output
	sort.Slice(results, func(i, j int) bool {
		return results[i].PrincipalArn < results[j].PrincipalArn
	})

	return results
}
