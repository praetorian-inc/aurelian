package aws

import (
	"encoding/json"
	"sort"
	"sync"

	"github.com/praetorian-inc/nebula/pkg/types"
)

// PrincipalResult represents a single principal's complete permissions
type PrincipalResult struct {
	PrincipalArn  string              `json:"principal_arn"`
	AccountID     string              `json:"account_id"`
	ResourcePerms map[string][]string `json:"resource_permissions"`
}

// PrincipalPolicies holds all policy documents associated with a principal
type PrincipalPolicies struct {
	IdentityPolicies    []*types.Policy // Inline and attached policies
	PermissionsBoundary *types.Policy   // Permission boundary if present
	Groups              []string        // Group memberships (for users)
	GroupPolicies       []*types.Policy // Group policies (for users)
}

// ResourcePermission represents what a principal can do with a resource
type ResourcePermission struct {
	Resource       string            // ARN of the resource
	AllowedActions []*ResourceAction // Action being evaluated
	DeniedActions  []*ResourceAction // Action being evaluated

	// Internal mutex for concurrent updates
	mu sync.RWMutex
}

type ResourceAction struct {
	Name             string
	EvaluationResult *EvaluationResult
}

// AddAction safely adds an action to the appropriate list
func (rp *ResourcePermission) AddAction(action string, eval *EvaluationResult) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if eval.Allowed {
		rp.AllowedActions = append(rp.AllowedActions, &ResourceAction{
			Name:             action,
			EvaluationResult: eval,
		})
	} else {
		rp.DeniedActions = append(rp.DeniedActions, &ResourceAction{
			Name:             action,
			EvaluationResult: eval,
		})
	}
}

// func containsString(slice []s

// AddResourcePermission safely adds or updates a resource permission
func (p *PrincipalPermissions) AddResourcePermission(resourceArn string, action string, allowed bool, eval *EvaluationResult) {
	// Get or create resource permission
	val, _ := p.ResourcePerms.LoadOrStore(resourceArn, &ResourcePermission{
		Resource:       resourceArn,
		AllowedActions: make([]*ResourceAction, 0),
		DeniedActions:  make([]*ResourceAction, 0),
	})

	rp := val.(*ResourcePermission)
	rp.AddAction(action, eval)
}

// GetResources returns a sorted list of all resource ARNs
func (p *PrincipalPermissions) GetResources() []string {
	resources := make([]string, 0)
	p.ResourcePerms.Range(func(key, value interface{}) bool {
		resources = append(resources, key.(string))
		return true
	})
	sort.Strings(resources)
	return resources
}

// MarshalJSON implements custom JSON marshaling
func (p *PrincipalPermissions) MarshalJSON() ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Convert sync.Map to regular map for marshaling
	resourcePerms := make(map[string]*ResourcePermission)
	p.ResourcePerms.Range(func(key, value interface{}) bool {
		resourcePerms[key.(string)] = value.(*ResourcePermission)
		return true
	})

	return json.Marshal(struct {
		PrincipalArn  string                         `json:"principal_arn"`
		ResourcePerms map[string]*ResourcePermission `json:"resource_permissions"`
	}{
		PrincipalArn:  p.PrincipalArn,
		ResourcePerms: resourcePerms,
	})
}

// PrincipalPermissions contains all permissions for a single principal
type PrincipalPermissions struct {
	PrincipalArn  string
	ResourcePerms sync.Map // Key is resource ARN, value is *ResourcePermission

	mu sync.RWMutex
}

// NewPrincipalPermissions creates a new PrincipalPermissions instance
func NewPrincipalPermissions(principalArn string) *PrincipalPermissions {
	return &PrincipalPermissions{
		PrincipalArn:  principalArn,
		ResourcePerms: sync.Map{},
	}
}
