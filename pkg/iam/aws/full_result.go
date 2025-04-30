package aws

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/nebula/pkg/types"
)

type FullResult struct {
	Principal interface{}                        `json:"principal"`
	Resource  *types.EnrichedResourceDescription `json:"resource"`
	Action    string                             `json:"action"`
	Result    *EvaluationResult                  `json:"result"`
}

func (fr *FullResult) UnmarshalJSON(data []byte) error {
	var intermediate struct {
		Principal json.RawMessage                    `json:"principal"`
		Resource  *types.EnrichedResourceDescription `json:"resource"`
		Action    string                             `json:"action"`
		Result    *EvaluationResult                  `json:"result"`
	}

	// Unmarshal into the intermediate structure
	if err := json.Unmarshal(data, &intermediate); err != nil {
		return fmt.Errorf("failed to unmarshal FullResult: %w", err)
	}

	fr.Resource = intermediate.Resource
	fr.Action = intermediate.Action
	fr.Result = intermediate.Result

	// First check if it's a simple string (service principal)
	var service string
	if err := json.Unmarshal(intermediate.Principal, &service); err == nil {
		// Verify it's actually a string and not an empty object
		if service != "" && service != "{}" {
			fr.Principal = service
			return nil
		}
	}

	// If not a string, it should be an object - try to detect its type
	var principalMap map[string]interface{}
	if err := json.Unmarshal(intermediate.Principal, &principalMap); err != nil {
		return fmt.Errorf("principal is neither a string nor an object: %w", err)
	}

	// Check for distinguishing fields to determine the type
	if _, hasUserName := principalMap["UserName"]; hasUserName {
		var user types.UserDL
		if err := json.Unmarshal(intermediate.Principal, &user); err != nil {
			return fmt.Errorf("failed to unmarshal user: %w", err)
		}
		fr.Principal = &user
		return nil
	}

	if _, hasRoleName := principalMap["RoleName"]; hasRoleName {
		var role types.RoleDL
		if err := json.Unmarshal(intermediate.Principal, &role); err != nil {
			return fmt.Errorf("failed to unmarshal role: %w", err)
		}
		fr.Principal = &role
		return nil
	}

	if _, hasGroupName := principalMap["GroupName"]; hasGroupName {
		var group types.GroupDL
		if err := json.Unmarshal(intermediate.Principal, &group); err != nil {
			return fmt.Errorf("failed to unmarshal group: %w", err)
		}
		fr.Principal = &group
		return nil
	}

	// If we can't determine the type, store it as a generic map
	fr.Principal = principalMap
	return nil
}

func (ps *PermissionsSummary) FullResults() []FullResult {
	results := make([]FullResult, 0)

	ps.Permissions.Range(func(key, value interface{}) bool {
		if perms, ok := value.(*PrincipalPermissions); ok {
			// Convert ResourcePerms sync.Map to map, skipping empty resources
			perms.ResourcePerms.Range(func(resKey, resValue interface{}) bool {
				if resPerm, ok := resValue.(*ResourcePermission); ok {
					// Only include resources that have allowed or denied actions
					if len(resPerm.AllowedActions) > 0 {
						resArn := resKey.(string)

						// Get the resource from the cache
						if resource, ok := resourceCache[resArn]; ok {
							for _, action := range resPerm.AllowedActions {
								if principal, ok := userCache[perms.PrincipalArn]; ok {
									results = append(results, FullResult{
										Principal: principal,
										Resource:  resource,
										Action:    action.Name,
										Result:    action.EvaluationResult,
									})
								} else if principal, ok := roleCache[perms.PrincipalArn]; ok {
									results = append(results, FullResult{
										Principal: principal,
										Resource:  resource,
										Action:    action.Name,
										Result:    action.EvaluationResult,
									})
								} else if principal, ok := groupCache[perms.PrincipalArn]; ok {
									results = append(results, FullResult{
										Principal: principal,
										Resource:  resource,
										Action:    action.Name,
										Result:    action.EvaluationResult,
									})
								} else {
									results = append(results, FullResult{
										Principal: perms.PrincipalArn,
										Resource:  resource,
										Action:    action.Name,
										Result:    action.EvaluationResult,
									})
								}

							}
						}

					}
				}
				return true
			})
		}
		return true
	})

	return results
}
