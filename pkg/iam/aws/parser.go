package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

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
							actions = append(actions, resPerm.AllowedActions...)
						}

						// Add denied actions (if you want to include them)
						// if len(resPerm.DeniedActions) > 0 {
						//     actions = append(actions, resPerm.DeniedActions...)
						// }

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
	Resource       string   // ARN of the resource
	AllowedActions []string // Actions explicitly allowed on this resource
	DeniedActions  []string // Actions explicitly denied on this resource
	CrossAccount   bool     // Whether this is a cross-account access
	ReasonAllowed  string   // Description of why access is allowed
	ReasonDenied   string   // Description of why access is denied

	// Internal mutex for concurrent updates
	mu sync.RWMutex
}

// AddAction safely adds an action to the appropriate list
func (rp *ResourcePermission) AddAction(action string, allowed bool, reason string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if allowed {
		if !containsString(rp.AllowedActions, action) {
			rp.AllowedActions = append(rp.AllowedActions, action)
			rp.ReasonAllowed = reason
		}
	} else {
		if !containsString(rp.DeniedActions, action) {
			rp.DeniedActions = append(rp.DeniedActions, action)
			rp.ReasonDenied = reason
		}
	}
}

func containsString(slice []string, target string) bool {
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}

// MarshalJSON implements custom JSON marshaling
func (rp *ResourcePermission) MarshalJSON() ([]byte, error) {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	// Sort actions for consistent output
	sort.Strings(rp.AllowedActions)
	sort.Strings(rp.DeniedActions)

	type Alias ResourcePermission
	return json.Marshal(&struct {
		*Alias
		AllowedActions []string `json:"allowed_actions"`
		DeniedActions  []string `json:"denied_actions"`
	}{
		Alias:          (*Alias)(rp),
		AllowedActions: rp.AllowedActions,
		DeniedActions:  rp.DeniedActions,
	})
}

// AddResourcePermission safely adds or updates a resource permission
func (p *PrincipalPermissions) AddResourcePermission(resourceArn string, action string, allowed bool, eval *EvaluationResult) {
	// Get or create resource permission
	val, _ := p.ResourcePerms.LoadOrStore(resourceArn, &ResourcePermission{
		Resource:       resourceArn,
		AllowedActions: make([]string, 0),
		DeniedActions:  make([]string, 0),
		CrossAccount:   eval.CrossAccountAccess,
	})

	rp := val.(*ResourcePermission)
	rp.AddAction(action, allowed, eval.EvaluationDetails)
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

	// Cache maps for faster lookups
	policyCache   sync.Map                                      // ARN -> Policy
	roleCache     sync.Map                                      // ARN -> Role
	userCache     sync.Map                                      // ARN -> User
	groupCache    sync.Map                                      // ARN -> Group
	resourceCache map[string]*types.EnrichedResourceDescription // ARN -> Resource
	evaluator     *PolicyEvaluator
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
	for i := range ga.policyData.Gaad.Policies {
		policy := &ga.policyData.Gaad.Policies[i]
		ga.policyCache.Store(policy.Arn, policy)
	}

	// Cache roles
	for i := range ga.policyData.Gaad.RoleDetailList {
		role := &ga.policyData.Gaad.RoleDetailList[i]
		ga.roleCache.Store(role.Arn, role)
	}

	// Cache users
	for i := range ga.policyData.Gaad.UserDetailList {
		user := &ga.policyData.Gaad.UserDetailList[i]
		ga.userCache.Store(user.Arn, user)
	}

	// Cache groups
	for i := range ga.policyData.Gaad.GroupDetailList {
		group := &ga.policyData.Gaad.GroupDetailList[i]
		ga.groupCache.Store(group.Arn, group)
	}

	// Cache resources
	ga.resourceCache = make(map[string]*types.EnrichedResourceDescription)
	if ga.policyData.Resources != nil {
		for i := range *ga.policyData.Resources {
			resource := &(*ga.policyData.Resources)[i]
			arn := resource.Arn.String()
			ga.resourceCache[arn] = resource
			slog.Debug(fmt.Sprintf("Cached resource: %s", arn))
		}
	}
}

// getPolicyByArn retrieves a policy using the cache
func (ga *GaadAnalyzer) getPolicyByArn(arn string) *types.PoliciesDL {
	if val, ok := ga.policyCache.Load(arn); ok {
		if policy, ok := val.(*types.PoliciesDL); ok {
			return policy
		}
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
	for arn := range ga.resourceCache {
		if pattern.MatchString(arn) {
			resources = append(resources, ga.resourceCache[arn])
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

	// Process users
	for _, user := range ga.policyData.Gaad.UserDetailList {
		wg.Add(1)
		go ga.processUserPermissions(user, summary, &wg)
	}

	// Process roles
	// for _, role := range ga.policyData.Gaad.RoleDetailList {
	// 	wg.Add(1)
	// 	go ga.processRolePermissions(role, summary, &wg)
	// }

	wg.Wait()
	return summary, nil
}

func (ga *GaadAnalyzer) evaluatePermissions(principalArn string, policies []*types.Policy, summary *PermissionsSummary) {
	// Extract unique resources and actions from policies
	resources := make(map[string]bool)
	allActions := make(map[string]bool)

	// First pass - collect all raw actions and resources
	for _, policy := range policies {
		for _, statement := range *policy.Statement {
			// Handle regular Actions
			if statement.Action != nil {
				expandedActions := expandActionsWithStage(*statement.Action)
				for _, action := range expandedActions {
					allActions[action] = true
				}
			}

			// Handle NotAction by getting all possible actions and removing matches
			if statement.NotAction != nil {
				notActions := expandActionsWithStage(*statement.NotAction)
				for action := range allActions {
					for _, notAction := range notActions {
						if strings.HasPrefix(action, notAction) {
							delete(allActions, action)
						}
					}
				}
			}

			// Collect Resources
			if statement.Resource != nil {
				for _, resource := range *statement.Resource {
					resources[resource] = true
				}
			}
		}
	}

	// Create worker pool for concurrent evaluation
	workerCount := 10
	type workItem struct {
		resource *types.EnrichedResourceDescription
		action   string
	}
	workChan := make(chan workItem)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for work := range workChan {
				// Create evaluation request
				req := &EvaluationRequest{
					Action:   work.action,
					Resource: work.resource.Arn.String(),
					Context: &RequestContext{
						PrincipalArn: principalArn,
						ResourceTags: work.resource.Tags(),
						AccountId:    work.resource.AccountId,
						CurrentTime:  time.Now(),
					},
				}
				slog.Debug(fmt.Sprintf("EvaluationRequest: %s", req.String()))

				// Evaluate permissions
				result, err := ga.evaluator.Evaluate(req)
				if err != nil {
					slog.Error("Error evaluating permissions",
						"principal", principalArn,
						"resource", work.resource,
						"action", work.action,
						"error", err)
					continue
				}

				slog.Debug(fmt.Sprintf("EvaluationRequest: %s, EvaluationResult: %s", req.String(), result.String()))

				// Record result
				summary.AddPermission(principalArn, work.resource.Arn.String(), work.action, result.Allowed, result)
			}
		}()
	}

	// Send work items - evaluate each resource/action combination
	for action := range allActions {
		for _, resource := range ga.getResourcesByAction(Action(action)) {
			workChan <- workItem{
				resource: resource,
				action:   action,
			}
		}
	}

	// Close channel and wait for completion
	close(workChan)
	wg.Wait()
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
func (ga *GaadAnalyzer) processUserPermissions(user types.UserDL, summary *PermissionsSummary, wg *sync.WaitGroup) {
	defer wg.Done()

	// Create identity statements list
	identityStatements := types.PolicyStatementList{}

	// Add inline policies
	for _, policy := range user.UserPolicyList {
		if policy.PolicyDocument.Statement != nil {
			// Decorate the policy with the user's ARN
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
					// Decorate the policy with the user's ARN
					for j := range *policy.PolicyVersionList[i].Document.Statement {
						(*policy.PolicyVersionList[i].Document.Statement)[j].OriginArn = attachedPolicy.PolicyArn
					}
					identityStatements = append(identityStatements, *policy.PolicyVersionList[i].Document.Statement...)
				}
			}
			// if doc := ga.getDefaultPolicyDocument(policy); doc != nil && doc.Statement != nil {
			// 	identityStatements = append(identityStatements, *doc.Statement...)
			// }
		}
	}

	// Add group policies
	for _, groupName := range user.GroupList {
		if group, exists := ga.getGroupByName(groupName); exists {
			// Add group inline policies
			for _, policy := range group.GroupPolicyList {
				if policy.PolicyDocument.Statement != nil {
					// Decorate the policy with the group's ARN
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
						// Decorate the policy with the group's ARN
						for i := range *doc.Statement {
							(*doc.Statement)[i].OriginArn = attachedPolicy.PolicyArn
						}
						identityStatements = append(identityStatements, *doc.Statement...)
					}
				}
			}
		}
	}

	// Now we can evaluate permissions properly
	resources := make(map[string]bool)
	allActions := make(map[string]bool)

	// Extract resources and actions from identityStatements
	for _, statement := range identityStatements {
		// Handle regular Actions
		if statement.Action != nil {
			expandedActions := expandActionsWithStage(*statement.Action)
			for _, action := range expandedActions {
				allActions[action] = true
			}
		}

		// Handle Resources
		if statement.Resource != nil {
			for _, resource := range *statement.Resource {
				resources[resource] = true
			}
		}
	}

	// Create worker pool
	workerCount := 10
	type workItem struct {
		resource *types.EnrichedResourceDescription
		action   string
	}
	workChan := make(chan workItem)
	var evalWg sync.WaitGroup

	// Start workers
	for i := 0; i < workerCount; i++ {
		evalWg.Add(1)
		go func() {
			defer evalWg.Done()
			for work := range workChan {
				// Create evaluation request with identity statements
				req := &EvaluationRequest{
					Action:             work.action,
					Resource:           work.resource.Arn.String(),
					IdentityStatements: &identityStatements, // Pass the identity statements
					Context: &RequestContext{
						PrincipalArn: user.Arn,
						// Add other context as needed
					},
				}

				// Evaluate permissions
				result, err := ga.evaluator.Evaluate(req)
				if err != nil {
					slog.Error("Error evaluating permissions",
						"principal", user.Arn,
						"resource", work.resource,
						"action", work.action,
						"error", err)
					continue
				}

				slog.Debug(fmt.Sprintf("EvaluationRequest: %s, EvaluationResult: %s", req.String(), result.String()))

				// Record result
				summary.AddPermission(user.Arn, work.resource.Arn.String(), work.action, result.Allowed, result)
			}
		}()
	}

	// Send work items
	for action := range allActions {
		if isPrivEscAction(action) {
			for _, resource := range ga.getResourcesByAction(Action(action)) {
				workChan <- workItem{
					resource: resource,
					action:   action,
				}
			}
		}
	}

	// Close channel and wait
	close(workChan)
	evalWg.Wait()
}

func (ga *GaadAnalyzer) processRolePermissions(role types.RoleDL, summary *PermissionsSummary, wg *sync.WaitGroup) {
	defer wg.Done()

	allPolicies := &PrincipalPolicies{
		IdentityPolicies: make([]*types.Policy, 0),
	}

	// Add inline policies
	for _, policy := range role.RolePolicyList {
		// Decorate the policy with the role's ARN
		for stmt := range *policy.PolicyDocument.Statement {
			(*policy.PolicyDocument.Statement)[stmt].OriginArn = role.Arn
		}
		allPolicies.IdentityPolicies = append(allPolicies.IdentityPolicies, &policy.PolicyDocument)
	}

	// Add managed policies
	for _, attachedPolicy := range role.AttachedManagedPolicies {
		if policy := ga.getPolicyByArn(attachedPolicy.PolicyArn); policy != nil {
			if doc := ga.getDefaultPolicyDocument(policy); doc != nil {
				// Decorate the policy with the role's ARN
				for stmt := range *doc.Statement {
					(*doc.Statement)[stmt].OriginArn = attachedPolicy.PolicyArn
				}
				allPolicies.IdentityPolicies = append(allPolicies.IdentityPolicies, doc)
			}
		}
	}

	// Set permissions boundary if present
	// if len(role.PermissionsBoundary.PermissionsBoundaryArn) > 0 {
	// 	if boundaryPolicy := ga.getPolicyByArn(role.PermissionsBoundary.PermissionsBoundaryArn); boundaryPolicy != nil {
	// 		if boundaryDoc := ga.getDefaultPolicyDocument(boundaryPolicy); boundaryDoc != nil {
	// 			allPolicies.PermissionsBoundary = boundaryDoc
	// 		}
	// 	}
	// }

	// Evaluate permissions with all policies
	ga.evaluatePermissions(role.Arn, allPolicies.IdentityPolicies, summary)
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
