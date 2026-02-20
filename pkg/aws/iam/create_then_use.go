package iam

import (
	"github.com/praetorian-inc/aurelian/pkg/types"
	"log/slog"
	"strings"

)

// createThenUsePair defines a "create-then-use" attack pattern where
// a principal who can create a resource controls its name, enabling them
// to always satisfy their own resource-scoped "use" permission.
type createThenUsePair struct {
	createAction    string // e.g. "codebuild:CreateProject"
	useActions      []string // e.g. ["codebuild:StartBuild", "codebuild:StartBuildBatch"]
	serviceResource string // e.g. "codebuild.amazonaws.com"
}

// createThenUsePairs enumerates all known create-then-use attack patterns.
var createThenUsePairs = []createThenUsePair{
	{
		createAction:    "codebuild:CreateProject",
		useActions:      []string{"codebuild:StartBuild", "codebuild:StartBuildBatch"},
		serviceResource: "codebuild.amazonaws.com",
	},
}

// applyCreateThenUseEdges adds synthetic permissions for "create-then-use" patterns.
//
// When a principal has a "create" action allowed on a service resource (e.g.,
// codebuild:CreateProject on codebuild.amazonaws.com), the attacker controls
// the resource name. If the principal's raw IAM policies also contain an Allow
// for the corresponding "use" action (e.g., codebuild:StartBuild), the attacker
// can always choose a name that matches their StartBuild resource pattern.
// However, the evaluator may not find a matching existing resource and thus
// never writes the "use" edge. This function fills that gap.
//
// The function also validates that the resource patterns for the create and use
// actions have compatible region/account segments, since the attacker controls
// the resource name but not the region or account ID.
func (s *AnalyzerState) applyCreateThenUseEdges(summary *PermissionsSummary) {
	for _, pair := range createThenUsePairs {
		summary.Permissions.Range(func(key, value any) bool {
			principalArn := key.(string)
			perms := value.(*PrincipalPermissions)

			if !hasAllowedActionOnResource(perms, pair.createAction, pair.serviceResource) {
				return true // continue — principal can't create
			}

			// Get the resource patterns from the create action's Allow statements
			createResources := s.getStmtResources(principalArn, pair.createAction)

			for _, useAction := range pair.useActions {
				if hasAllowedActionOnAnyResource(perms, useAction) {
					continue // already has a "use" edge
				}

				useResources := s.getStmtResources(principalArn, useAction)
				if len(useResources) == 0 {
					continue // no Allow statement for the use action
				}

				if !resourcePatternsOverlap(createResources, useResources) {
					slog.Info("Skipping synthetic edge: create/use resource patterns do not overlap",
						"principal", principalArn,
						"createAction", pair.createAction,
						"useAction", useAction,
						"createResources", createResources,
						"useResources", useResources,
					)
					continue
				}

				slog.Info("Adding synthetic create-then-use edge",
					"principal", principalArn,
					"action", useAction,
					"resource", pair.serviceResource,
				)

				syntheticResult := &EvaluationResult{
					Allowed:           true,
					PolicyResult:      NewPolicyResult(),
					EvaluationDetails: "Synthetic: create-then-use pattern — principal controls resource name",
					Action:            Action(useAction),
				}
				summary.AddPermission(principalArn, pair.serviceResource, useAction, true, syntheticResult)
			}

			return true
		})
	}
}

// hasAllowedActionOnResource checks whether a principal already has a specific
// action allowed on a specific resource in the permissions summary.
func hasAllowedActionOnResource(perms *PrincipalPermissions, action, resource string) bool {
	val, ok := perms.ResourcePerms.Load(resource)
	if !ok {
		return false
	}
	rp := val.(*ResourcePermission)
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	for _, a := range rp.AllowedActions {
		if strings.EqualFold(a.Name, action) {
			return true
		}
	}
	return false
}

// hasAllowedActionOnAnyResource checks whether a principal has a specific action
// allowed on any resource.
func hasAllowedActionOnAnyResource(perms *PrincipalPermissions, action string) bool {
	found := false
	perms.ResourcePerms.Range(func(_, value any) bool {
		rp := value.(*ResourcePermission)
		rp.mu.RLock()
		defer rp.mu.RUnlock()
		for _, a := range rp.AllowedActions {
			if strings.EqualFold(a.Name, action) {
				found = true
				return false // stop iteration
			}
		}
		return true
	})
	return found
}

// getStmtResources returns the Resource patterns from all Allow statements in a
// principal's raw IAM policies that grant the given action. Returns nil if no
// matching Allow statement is found.
func (s *AnalyzerState) getStmtResources(principalArn, action string) []string {
	var resources []string

	collectFromStatements := func(stmts *types.PolicyStatementList) {
		if stmts == nil {
			return
		}
		for _, stmt := range *stmts {
			if stmtAllowsAction(&stmt, action) {
				if stmt.Resource != nil {
					resources = append(resources, (*stmt.Resource)...)
				} else {
					// No Resource field means implicit "*"
					resources = append(resources, "*")
				}
			}
		}
	}

	collectFromManagedPolicies := func(attachedPolicies []types.ManagedPolicy) {
		for _, attached := range attachedPolicies {
			if pol := s.getPolicyByArn(attached.PolicyArn); pol != nil {
				if doc := pol.DefaultPolicyDocument(); doc != nil {
					collectFromStatements(doc.Statement)
				}
			}
		}
	}

	// Try role cache first
	if role, ok := s.RoleCache[principalArn]; ok {
		for _, policy := range role.RolePolicyList {
			collectFromStatements(policy.PolicyDocument.Statement)
		}
		collectFromManagedPolicies(role.AttachedManagedPolicies)
		return resources
	}

	// Try user cache
	if user, ok := s.UserCache[principalArn]; ok {
		for _, policy := range user.UserPolicyList {
			collectFromStatements(policy.PolicyDocument.Statement)
		}
		collectFromManagedPolicies(user.AttachedManagedPolicies)
		// Check group policies
		for _, groupName := range user.GroupList {
			for _, group := range s.GroupCache {
				if group.GroupName != groupName {
					continue
				}
				for _, policy := range group.GroupPolicyList {
					collectFromStatements(policy.PolicyDocument.Statement)
				}
				collectFromManagedPolicies(group.AttachedManagedPolicies)
			}
		}
		return resources
	}

	return nil
}

// resourcePatternsOverlap checks whether any create resource pattern and any use
// resource pattern could refer to the same region+account combination.
//
// The attacker controls the resource name (e.g., the project name in
// arn:aws:codebuild:<region>:<account>:project/<name>) but NOT the region or
// account. So we split each ARN pattern into segments and verify that the
// non-controllable parts (region, account) are compatible between the create
// and use patterns.
func resourcePatternsOverlap(createResources, useResources []string) bool {
	for _, cr := range createResources {
		for _, ur := range useResources {
			if arnPatternsCompatible(cr, ur) {
				return true
			}
		}
	}
	return false
}

// arnPatternsCompatible checks if two ARN patterns (or wildcards) could refer
// to the same region and account. Both patterns may contain wildcards.
//
// ARN format: arn:partition:service:region:account:resource
// We check that segments 0-4 (partition, service, region, account) are
// compatible. Segment 5+ (resource) is ignored since the attacker controls it.
func arnPatternsCompatible(a, b string) bool {
	// Wildcards are universally compatible
	if a == "*" || b == "*" {
		return true
	}

	aParts := strings.SplitN(a, ":", 6)
	bParts := strings.SplitN(b, ":", 6)

	// If either doesn't look like an ARN, be conservative and say they overlap
	if len(aParts) < 5 || len(bParts) < 5 {
		return true
	}

	// Check segments 0-4: arn, partition, service, region, account
	for i := 0; i < 5; i++ {
		if !MatchesPattern(aParts[i], bParts[i]) && !MatchesPattern(bParts[i], aParts[i]) {
			return false
		}
	}
	return true
}

// stmtAllowsAction checks whether a single policy statement is an Allow that
// covers the given action (handling wildcards and NotAction).
func stmtAllowsAction(stmt *types.PolicyStatement, action string) bool {
	if !strings.EqualFold(stmt.Effect, "allow") {
		return false
	}
	// Check Action field
	if stmt.Action != nil {
		for _, policyAction := range *stmt.Action {
			if MatchesPattern(policyAction, action) {
				return true
			}
		}
		return false
	}
	// Check NotAction field — allows everything except the listed actions
	if stmt.NotAction != nil {
		for _, excluded := range *stmt.NotAction {
			if MatchesPattern(excluded, action) {
				return false
			}
		}
		return true
	}
	return false
}
