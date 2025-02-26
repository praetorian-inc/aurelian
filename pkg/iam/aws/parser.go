package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// Cache maps for faster lookups
var policyCache map[string]*types.PoliciesDL                    // ARN -> Policy
var roleCache map[string]*types.RoleDL                          // ARN -> Role
var userCache map[string]*types.UserDL                          // ARN -> User
var groupCache map[string]*types.GroupDL                        // ARN -> Group
var resourceCache map[string]*types.EnrichedResourceDescription // ARN -> Resource

// PermissionsSummary maps principal ARNs to their permissions
type PermissionsSummary struct {
	Permissions sync.Map // Key is principal ARN, value is *PrincipalPermissions
}

// GetResults returns analyzed permissions for each principal, excluding resources with no actions
func (ps *PermissionsSummary) GetResults() []PrincipalResult {
	results := make([]PrincipalResult, 0)

	ps.Permissions.Range(func(key, value interface{}) bool {
		if perms, ok := value.(*PrincipalPermissions); ok {
			result := PrincipalResult{
				PrincipalArn:  perms.PrincipalArn,
				AccountID:     perms.AccountID,
				ResourcePerms: make(map[string][]string),
			}

			// Convert ResourcePerms sync.Map to map, skipping empty resources
			perms.ResourcePerms.Range(func(resKey, resValue interface{}) bool {
				if resPerm, ok := resValue.(*ResourcePermission); ok {
					// Only include resources that have allowed or denied actions
					if len(resPerm.AllowedActions) > 0 || len(resPerm.DeniedActions) > 0 {
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
					if len(resPerm.AllowedActions) > 0 || len(resPerm.DeniedActions) > 0 {
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
								}
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

// NewPermissionsSummary creates a new empty PermissionsSummary
func NewPermissionsSummary() *PermissionsSummary {
	return &PermissionsSummary{
		Permissions: sync.Map{},
	}
}

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

// func containsString(slice []string, target string) bool {
// 	for _, item := range slice {
// 		if item == target {
// 			return true
// 		}
// 	}
// 	return false
// }

// MarshalJSON implements custom JSON marshaling
// func (rp *ResourcePermission) MarshalJSON() ([]byte, error) {
// 	rp.mu.RLock()
// 	defer rp.mu.RUnlock()

// 	// Sort actions for consistent output
// 	sort.Strings(rp.AllowedActions)
// 	sort.Strings(rp.DeniedActions)

// 	type Alias ResourcePermission
// 	return json.Marshal(&struct {
// 		*Alias
// 		AllowedActions []string `json:"allowed_actions"`
// 		DeniedActions  []string `json:"denied_actions"`
// 	}{
// 		Alias:          (*Alias)(rp),
// 		AllowedActions: rp.AllowedActions,
// 		DeniedActions:  rp.DeniedActions,
// 	})
// }

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
		AccountID     string                         `json:"account_id"`
		ResourcePerms map[string]*ResourcePermission `json:"resource_permissions"`
	}{
		PrincipalArn:  p.PrincipalArn,
		AccountID:     p.AccountID,
		ResourcePerms: resourcePerms,
	})
}

// AddPermission safely adds or updates a permission for a principal
func (ps *PermissionsSummary) AddPermission(principalArn, resourceArn, action string, allowed bool, eval *EvaluationResult) {
	// Get or create principal permissions
	val, _ := ps.Permissions.LoadOrStore(principalArn, NewPrincipalPermissions(principalArn, getAccountFromArn(principalArn)))
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

// GaadAnalyzer handles efficient analysis of GAAD policy data
type GaadAnalyzer struct {
	policyData *PolicyData

	evaluator *PolicyEvaluator
}

// NewGaadAnalyzer creates a new analyzer and initializes caches
func NewGaadAnalyzer(pd *PolicyData, evaluator *PolicyEvaluator) *GaadAnalyzer {
	ga := &GaadAnalyzer{
		policyData: pd,
		evaluator:  evaluator,
	}
	ga.initializeCaches()
	return ga
}

// initializeCaches populates lookup maps for faster access
func (ga *GaadAnalyzer) initializeCaches() {
	// Cache policies
	policyCache = make(map[string]*types.PoliciesDL)
	for i := range ga.policyData.Gaad.Policies {
		policy := &ga.policyData.Gaad.Policies[i]
		policyCache[policy.Arn] = policy
	}

	// Cache roles
	roleCache = make(map[string]*types.RoleDL)
	for i := range ga.policyData.Gaad.RoleDetailList {
		role := &ga.policyData.Gaad.RoleDetailList[i]
		roleCache[role.Arn] = role
	}

	// Cache users
	userCache = make(map[string]*types.UserDL)
	for i := range ga.policyData.Gaad.UserDetailList {
		user := &ga.policyData.Gaad.UserDetailList[i]
		userCache[user.Arn] = user
	}

	// Cache groups
	groupCache = make(map[string]*types.GroupDL)
	for i := range ga.policyData.Gaad.GroupDetailList {
		group := &ga.policyData.Gaad.GroupDetailList[i]
		groupCache[group.Arn] = group
	}

	// Cache resources
	resourceCache = make(map[string]*types.EnrichedResourceDescription)
	if ga.policyData.Resources != nil {
		for i := range *ga.policyData.Resources {
			resource := &(*ga.policyData.Resources)[i]
			arn := resource.Arn.String()
			resourceCache[arn] = resource
		}
	}
}

// getPolicyByArn retrieves a policy using the cache
func (ga *GaadAnalyzer) getPolicyByArn(arn string) *types.PoliciesDL {
	if policy, ok := policyCache[arn]; ok {
		return policy
	}
	return nil
}

// getDefaultPolicyDocument retrieves the default policy version document
func (ga *GaadAnalyzer) getDefaultPolicyDocument(policy *types.PoliciesDL) *types.Policy {
	for _, version := range policy.PolicyVersionList {
		if version.IsDefaultVersion {
			return &version.Document
		}
	}
	return nil
}

func (ga *GaadAnalyzer) getResources(pattern *regexp.Regexp) []*types.EnrichedResourceDescription {
	resources := make([]*types.EnrichedResourceDescription, 0)
	for arn := range resourceCache {
		if pattern.MatchString(arn) {
			resources = append(resources, resourceCache[arn])
		}
	}

	return resources
}

func (ga *GaadAnalyzer) getResourcesByAction(action Action) []*types.EnrichedResourceDescription {
	resources := make([]*types.EnrichedResourceDescription, 0)
	patterns := GetResourcePatternsFromAction(action)

	for _, pattern := range patterns {
		resources = append(resources, ga.getResources(pattern)...)
	}

	return resources
}

// AnalyzePrincipalPermissions processes permissions for IAM principals concurrently
func (ga *GaadAnalyzer) AnalyzePrincipalPermissions() (*PermissionsSummary, error) {
	summary := NewPermissionsSummary()
	var wg sync.WaitGroup

	// Create buffered channel for evaluation requests
	// Use buffer to prevent blocking
	evalChan := make(chan *EvaluationRequest, 1000)

	// Start evaluation workers
	var evalWg sync.WaitGroup
	ga.startEvaluationWorkers(evalChan, summary, &evalWg)

	// Process users
	for _, user := range ga.policyData.Gaad.UserDetailList {
		wg.Add(1)
		go func(u types.UserDL) {
			defer wg.Done()
			ga.processUserPermissions(u, evalChan)
		}(user)
	}

	for _, role := range ga.policyData.Gaad.RoleDetailList {
		wg.Add(1)
		go func(r types.RoleDL) {
			defer wg.Done()
			ga.processRolePermissions(r, evalChan)
		}(role)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ga.generateServicePrincipalEvaluations(evalChan)
	}()

	wg.Wait()
	return summary, nil
}

func (ga *GaadAnalyzer) generateServicePrincipalEvaluations(evalChan chan *EvaluationRequest) {

	// Process resource policies
	for resourceArn := range ga.policyData.ResourcePolicies {
		policy := ga.policyData.ResourcePolicies[resourceArn]
		evalReq := ga.generateServiceEvaluations(resourceArn, policy)
		if evalReq != nil {
			evalChan <- evalReq
		}
	}

	// Proccess AssumeRole policies
	for _, role := range ga.policyData.Gaad.RoleDetailList {
		for i, stmt := range *role.AssumeRolePolicyDocument.Statement {
			(*role.AssumeRolePolicyDocument.Statement)[i].OriginArn = role.Arn
			(*role.AssumeRolePolicyDocument.Statement)[i].Resource = &types.DynaString{role.Arn}
			if stmt.Principal != nil && stmt.Principal.Service != nil {
				for _, service := range *stmt.Principal.Service {
					for _, action := range *stmt.Action {
						if isPrivEscAction(action) {

							accountID, tags := getResourceDeets(role.Arn)

							evalReq := &EvaluationRequest{
								Action:             action,
								Resource:           role.Arn,
								IdentityStatements: role.AssumeRolePolicyDocument.Statement,
								Context: &RequestContext{
									PrincipalArn: service,
									ResourceTags: tags,
									AccountId:    accountID,
									CurrentTime:  time.Now(),
								},
							}
							evalChan <- evalReq
						}
					}
				}
			}
		}
	}
}

func getResourceDeets(resourceArn string) (string, map[string]string) {
	resource, ok := resourceCache[resourceArn]
	if !ok {
		slog.Debug("Resource not found for ARN", "arn", resourceArn)
		parsed, err := arn.Parse(resourceArn)
		if err != nil {
			slog.Error("Failed to parse ARN", "arn", resourceArn, "error", err)
			return "", nil
		}
		return parsed.AccountID, nil
	}
	return resource.AccountId, resource.Tags()
}

func (ga *GaadAnalyzer) generateServiceEvaluations(resourceArn string, policy *types.Policy) *EvaluationRequest {
	if policy.Statement != nil {
		for i := range *policy.Statement {
			(*policy.Statement)[i].OriginArn = resourceArn
			if (*policy.Statement)[i].Principal != nil && (*policy.Statement)[i].Principal.Service != nil {
				for _, service := range *(*policy.Statement)[i].Principal.Service {
					for _, action := range *(*policy.Statement)[i].Action {
						if isPrivEscAction(action) {

							accountID, tags := getResourceDeets(resourceArn)

							evalReq := &EvaluationRequest{
								Action:             action,
								Resource:           resourceArn,
								IdentityStatements: policy.Statement,
								Context: &RequestContext{
									PrincipalArn: service,
									ResourceTags: tags,
									AccountId:    accountID,
									CurrentTime:  time.Now(),
								},
							}
							return evalReq
						}
					}
				}
			}
		}
	}
	return nil
}

// Helper function to use AwsExpandActionsStage
func expandActionsWithStage(actions types.DynaString) []string {
	expandedActions := make([]string, 0)
	ctx := context.WithValue(context.Background(), "metadata", modules.Metadata{Name: "AwsExpandActionsStage"})
	opts := []*types.Option{
		options.WithDefaultValue(options.LogLevelOpt, "debug"),
	}

	// Process each action
	for _, action := range actions {
		if strings.Contains(action, "*") {
			// Use the stage to expand wildcards
			for expAction := range stages.AwsExpandActionsStage(ctx, opts, stages.Generator([]string{action})) {
				expandedActions = append(expandedActions, expAction)
			}
		} else {
			// Add non-wildcard actions directly
			expandedActions = append(expandedActions, action)
		}
	}

	return expandedActions
}

// Modified process methods to gather all policies
func (ga *GaadAnalyzer) processUserPermissions(user types.UserDL, evalChan chan<- *EvaluationRequest) {
	// Create identity statements list
	identityStatements := types.PolicyStatementList{}
	boundaryStatements := types.PolicyStatementList{}

	// Add inline policies
	for _, policy := range user.UserPolicyList {
		if policy.PolicyDocument.Statement != nil {
			// Decorate with user's ARN
			for i := range *policy.PolicyDocument.Statement {
				(*policy.PolicyDocument.Statement)[i].OriginArn = user.Arn
			}
			identityStatements = append(identityStatements, *policy.PolicyDocument.Statement...)
		}
	}

	// Add managed policies
	for _, attachedPolicy := range user.AttachedManagedPolicies {
		if policy := ga.getPolicyByArn(attachedPolicy.PolicyArn); policy != nil {
			for i := range policy.PolicyVersionList {
				if policy.PolicyVersionList[i].IsDefaultVersion {
					// Decorate with policy ARN
					for j := range *policy.PolicyVersionList[i].Document.Statement {
						(*policy.PolicyVersionList[i].Document.Statement)[j].OriginArn = attachedPolicy.PolicyArn
					}
					identityStatements = append(identityStatements, *policy.PolicyVersionList[i].Document.Statement...)
				}
			}
		}
	}

	// Add permissions boundary
	if user.PermissionsBoundary != (types.ManagedPL{}) {
		if boundaryPolicy := ga.getPolicyByArn(user.PermissionsBoundary.PolicyArn); boundaryPolicy != nil {
			if boundaryDoc := ga.getDefaultPolicyDocument(boundaryPolicy); boundaryDoc != nil {
				for i := range *boundaryDoc.Statement {
					(*boundaryDoc.Statement)[i].OriginArn = user.PermissionsBoundary.PolicyArn
				}
				boundaryStatements = *boundaryDoc.Statement
			}
		}
	}

	// Process group policies
	for _, groupName := range user.GroupList {
		if group, exists := ga.getGroupByName(groupName); exists {
			// Add group inline policies
			for _, policy := range group.GroupPolicyList {
				if policy.PolicyDocument.Statement != nil {
					for i := range *policy.PolicyDocument.Statement {
						(*policy.PolicyDocument.Statement)[i].OriginArn = group.Arn
					}
					identityStatements = append(identityStatements, *policy.PolicyDocument.Statement...)
				}
			}
			// Add group managed policies
			for _, attachedPolicy := range group.AttachedManagedPolicies {
				if policy := ga.getPolicyByArn(attachedPolicy.PolicyArn); policy != nil {
					if doc := ga.getDefaultPolicyDocument(policy); doc != nil && doc.Statement != nil {
						for i := range *doc.Statement {
							(*doc.Statement)[i].OriginArn = attachedPolicy.PolicyArn
						}
						identityStatements = append(identityStatements, *doc.Statement...)
					}
				}
			}
		}
	}

	// Extract and process actions/resources
	allActions := ExtractActions(&identityStatements)

	// Generate evaluation requests
	for _, action := range allActions {
		if isPrivEscAction(action) {

			var tempBoundary types.PolicyStatementList
			deepCopy(boundaryStatements, tempBoundary)
			for _, resource := range ga.getResourcesByAction(Action(action)) {

				// For AssumeRole actions, update the resource in the policy document
				// Without the resource, the evaluator won't match the policy
				if action == "sts:AssumeRole" {
					role := roleCache[resource.Arn.String()]
					if role != nil {
						arpd := role.AssumeRolePolicyDocument
						for i := range *arpd.Statement {
							(*arpd.Statement)[i].Resource = &types.DynaString{resource.Arn.String()}
						}

						slog.Debug(fmt.Sprintf("AssumeRole policy for %s: %v", role.Arn, arpd.Statement))
						tempBoundary = append(tempBoundary, *arpd.Statement...)
					}
				}

				evalReq := &EvaluationRequest{
					Action:             action,
					Resource:           resource.Arn.String(),
					IdentityStatements: &identityStatements,
					BoundaryStatements: &tempBoundary,
					Context: &RequestContext{
						PrincipalArn: user.Arn,
						ResourceTags: resource.Tags(),
						AccountId:    resource.AccountId,
						CurrentTime:  time.Now(),
					},
				}
				evalChan <- evalReq
			}
		}
	}
}

func deepCopy(src, dst interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func ExtractActions(psl *types.PolicyStatementList) []string {
	actions := []string{}
	for _, statement := range *psl {
		if statement.Action != nil {
			expandedActions := expandActionsWithStage(*statement.Action)
			actions = append(actions, expandedActions...)
		}
	}
	return actions
}

func (ga *GaadAnalyzer) startEvaluationWorkers(evalChan <-chan *EvaluationRequest, summary *PermissionsSummary, wg *sync.WaitGroup) {
	numWorkers := runtime.NumCPU() * 3
	slog.Debug(fmt.Sprintf("Starting %d evaluation workers", numWorkers))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for req := range evalChan {
				result, err := ga.evaluator.Evaluate(req)
				if err != nil {
					slog.Error("Error evaluating permissions",
						"principal", req.Context.PrincipalArn,
						"resource", req.Resource,
						"action", req.Action,
						"error", err)
					continue
				}

				slog.Debug(fmt.Sprintf("EvaluationRequest: %s, EvaluationResult: %s",
					req.String(), result.String()))

				summary.AddPermission(req.Context.PrincipalArn, req.Resource,
					req.Action, result.Allowed, result)
			}
		}()
	}
}

func (ga *GaadAnalyzer) processRolePermissions(role types.RoleDL, evalChan chan<- *EvaluationRequest) {
	identityStatements := types.PolicyStatementList{}
	boundaryStatements := types.PolicyStatementList{}

	// Add inline policies
	for _, policy := range role.RolePolicyList {
		// Decorate the policy with the role's ARN
		for stmt := range *policy.PolicyDocument.Statement {
			(*policy.PolicyDocument.Statement)[stmt].OriginArn = role.Arn
		}
		identityStatements = append(identityStatements, *policy.PolicyDocument.Statement...)
	}

	// Add managed policies
	for _, attachedPolicy := range role.AttachedManagedPolicies {
		if policy := ga.getPolicyByArn(attachedPolicy.PolicyArn); policy != nil {
			if doc := ga.getDefaultPolicyDocument(policy); doc != nil {
				// Decorate the policy with the role's ARN
				for stmt := range *doc.Statement {
					(*doc.Statement)[stmt].OriginArn = attachedPolicy.PolicyArn
				}
				identityStatements = append(identityStatements, *doc.Statement...)
			}
		}
	}

	//Set permissions boundary if present
	if role.PermissionsBoundary != (types.ManagedPL{}) {
		if boundaryPolicy := ga.getPolicyByArn(role.PermissionsBoundary.PolicyArn); boundaryPolicy != nil {
			if boundaryDoc := ga.getDefaultPolicyDocument(boundaryPolicy); boundaryDoc != nil {
				for i := range *boundaryDoc.Statement {
					(*boundaryDoc.Statement)[i].OriginArn = role.PermissionsBoundary.PolicyArn
				}
				boundaryStatements = *boundaryDoc.Statement
			}
		}
	}

	// Extract and process actions/resources
	allActions := ExtractActions(&identityStatements)

	// Generate evaluation requests
	for _, action := range allActions {
		if isPrivEscAction(action) {

			var tempBoundary types.PolicyStatementList
			deepCopy(boundaryStatements, tempBoundary)

			for _, resource := range ga.getResourcesByAction(Action(action)) {
				// For AssumeRole actions, update the resource in the policy document
				// Without the resource, the evaluator won't match the policy
				if action == "sts:AssumeRole" {
					role := roleCache[resource.Arn.String()]
					if role != nil {
						arpd := role.AssumeRolePolicyDocument
						for i := range *arpd.Statement {
							(*arpd.Statement)[i].Resource = &types.DynaString{resource.Arn.String()}
						}

						slog.Debug(fmt.Sprintf("AssumeRole policy for %s: %v", role.Arn, arpd.Statement))
						tempBoundary = append(tempBoundary, *arpd.Statement...)
					}
				}
				evalReq := &EvaluationRequest{
					Action:             action,
					Resource:           resource.Arn.String(),
					IdentityStatements: &identityStatements,
					BoundaryStatements: &boundaryStatements,
					Context: &RequestContext{
						PrincipalArn: role.Arn,
						ResourceTags: resource.Tags(),
						AccountId:    resource.AccountId,
						CurrentTime:  time.Now(),
					},
				}
				evalChan <- evalReq
			}
		}
	}
}

// getGroupByName retrieves a group by name
func (ga *GaadAnalyzer) getGroupByName(name string) (*types.GroupDL, bool) {
	for _, group := range ga.policyData.Gaad.GroupDetailList {
		if group.GroupName == name {
			return &group, true
		}
	}
	return nil, false
}

// PrincipalPermissions contains all permissions for a single principal
type PrincipalPermissions struct {
	PrincipalArn  string
	AccountID     string
	ResourcePerms sync.Map // Key is resource ARN, value is *ResourcePermission

	mu sync.RWMutex
}

// NewPrincipalPermissions creates a new PrincipalPermissions instance
func NewPrincipalPermissions(principalArn string, accountId string) *PrincipalPermissions {
	return &PrincipalPermissions{
		PrincipalArn:  principalArn,
		AccountID:     accountId,
		ResourcePerms: sync.Map{},
	}
}

// Helper function to extract account ID from ARN
func getAccountFromArn(arnStr string) string {
	parts := strings.Split(arnStr, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func isPrivEscAction(action string) bool {
	slices.Contains(privEscActions, action)
	return slices.Contains(privEscActions, action)
}

var privEscActions = []string{
	"cloudformation:CreateChangeSet",
	"cloudformation:CreateStack",
	"cloudformation:ExecuteChangeSet",
	"cloudformation:SetStackPolicy",
	"cloudformation:UpdateStack",
	"cloudformation:UpdateStackSet",
	"codebuild:CreateProject",
	"codebuild:StartBuild",
	"codebuild:StartBuildBatch",
	"codebuild:UpdateProject",
	"codestar:AssociateTeamMember",
	"codestar:CreateProject",
	"datapipeline:CreatePipeline",
	"datapipeline:PutPipelineDefinition",
	"ec2:RunInstances",
	"glue:CreateDevEndpoint",
	"glue:UpdateDevEndpoint",
	"iam:AddUserToGroup",
	"iam:AttachGroupPolicy",
	"iam:AttachRolePolicy",
	"iam:AttachUserPolicy",
	"iam:CreateAccessKey",
	"iam:CreateLoginProfile",
	"iam:CreatePolicyVersion",
	"iam:PassRole",
	"iam:PutGroupPolicy",
	"iam:PutRolePolicy",
	"iam:PutUserPolicy",
	"iam:SetDefaultPolicyVersion",
	"iam:UpdateAssumeRolePolicy",
	"iam:UpdateLoginProfile",
	"lambda:CreateEventSourceMapping",
	"lambda:CreateFunction",
	"lambda:InvokeFunction",
	"lambda:UpdateFunctionCode",
	"sagemaker:CreateHyperParameterTuningJob",
	"sagemaker:CreateNotebookInstance",
	"sagemaker:CreatePresignedNotebookInstanceUrl",
	"sagemaker:CreateProcessingJob",
	"sagemaker:CreateTrainingJob",
	"sts:AssumeRole",
	"sts:AssumeRoleWithSAML",
	"sts:AssumeRoleWithWebIdentity",
	"sts:GetFederationToken",
}
