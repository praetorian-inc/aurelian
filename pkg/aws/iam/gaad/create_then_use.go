package gaad

import (
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// createThenUsePair defines a "create-then-use" attack pattern where
// a principal who can create a resource controls its name, enabling them
// to always satisfy their own resource-scoped "use" permission.
type createThenUsePair struct {
	createAction    string   // e.g. "codebuild:CreateProject"
	useActions      []string // e.g. ["codebuild:StartBuild", "codebuild:StartBuildBatch"]
	serviceResource string   // e.g. "codebuild.amazonaws.com"
}

// createThenUsePairs enumerates all known create-then-use attack patterns.
var createThenUsePairs = []createThenUsePair{
	{
		createAction:    "codebuild:CreateProject",
		useActions:      []string{"codebuild:StartBuild", "codebuild:StartBuildBatch"},
		serviceResource: "codebuild.amazonaws.com",
	},
}

// permissionIndex indexes evaluation results for fast lookup by
// (principal, resource, action). Built from []AWSIAMRelationship.
type permissionIndex struct {
	// principalResources[principalARN][resourceARN][action] = true
	principalResources map[string]map[string]map[string]bool
}

func newPermissionIndex(results []output.AWSIAMRelationship) *permissionIndex {
	idx := &permissionIndex{
		principalResources: make(map[string]map[string]map[string]bool),
	}
	for _, rel := range results {
		principalArn := rel.Principal.ARN
		resourceArn := rel.Resource.ARN
		action := rel.Action

		if idx.principalResources[principalArn] == nil {
			idx.principalResources[principalArn] = make(map[string]map[string]bool)
		}
		if idx.principalResources[principalArn][resourceArn] == nil {
			idx.principalResources[principalArn][resourceArn] = make(map[string]bool)
		}
		idx.principalResources[principalArn][resourceArn][action] = true
	}
	return idx
}

// hasActionOnResource checks whether a principal has a specific action allowed
// on a specific resource.
func (idx *permissionIndex) hasActionOnResource(principalArn, action, resource string) bool {
	resMap, ok := idx.principalResources[principalArn]
	if !ok {
		return false
	}
	actionMap, ok := resMap[resource]
	if !ok {
		return false
	}
	return actionMap[action]
}

// hasActionOnAnyResource checks whether a principal has a specific action
// allowed on any resource.
func (idx *permissionIndex) hasActionOnAnyResource(principalArn, action string) bool {
	resMap, ok := idx.principalResources[principalArn]
	if !ok {
		return false
	}
	for _, actionMap := range resMap {
		if actionMap[action] {
			return true
		}
	}
	return false
}

// synthesizeCreateThenUsePermissions adds synthetic permissions for "create-then-use" patterns.
//
// When a principal has a "create" action allowed on a service resource (e.g.,
// codebuild:CreateProject on codebuild.amazonaws.com), the attacker controls
// the resource name. If the principal's raw IAM policies also contain an Allow
// for the corresponding "use" action, the attacker can always choose a name
// that matches their resource pattern. However, the evaluator may not find a
// matching existing resource and thus never produces the "use" edge. This
// function fills that gap.
func synthesizeCreateThenUsePermissions(results []output.AWSIAMRelationship, state *AnalyzerState) []output.AWSIAMRelationship {
	idx := newPermissionIndex(results)
	var synthetic []output.AWSIAMRelationship

	for _, pair := range createThenUsePairs {
		for principalArn := range idx.principalResources {
			if !idx.hasActionOnResource(principalArn, pair.createAction, pair.serviceResource) {
				continue // principal can't create
			}

			createResources := getStmtResources(principalArn, pair.createAction, state)

			for _, useAction := range pair.useActions {
				if idx.hasActionOnAnyResource(principalArn, useAction) {
					continue // already has a "use" edge
				}

				useResources := getStmtResources(principalArn, useAction, state)
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

				principal := buildPrincipal(principalArn, state)
				resource := state.GetResource(pair.serviceResource)
				if resource == nil {
					slog.Debug("Service resource not found in cache",
						"service", pair.serviceResource)
					continue
				}

				synthetic = append(synthetic, output.AWSIAMRelationship{
					Principal: principal,
					Resource:  *resource,
					Action:    useAction,
				})
			}
		}
	}

	return append(results, synthetic...)
}

// getStmtResources returns the Resource patterns from all Allow statements in a
// principal's raw IAM policies that grant the given action.
func getStmtResources(principalArn, action string, state *AnalyzerState) []string {
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
					resources = append(resources, "*")
				}
			}
		}
	}

	collectFromManagedPolicies := func(attachedPolicies []types.ManagedPolicy) {
		for _, attached := range attachedPolicies {
			if pol := state.GetPolicyByArn(attached.PolicyArn); pol != nil {
				if doc := pol.DefaultPolicyDocument(); doc != nil {
					collectFromStatements(doc.Statement)
				}
			}
		}
	}

	// Try role first
	if role := state.GetRole(principalArn); role != nil {
		for _, policy := range role.RolePolicyList {
			collectFromStatements(policy.PolicyDocument.Statement)
		}
		collectFromManagedPolicies(role.AttachedManagedPolicies)
		return resources
	}

	// Try user
	if user := state.GetUser(principalArn); user != nil {
		for _, policy := range user.UserPolicyList {
			collectFromStatements(policy.PolicyDocument.Statement)
		}
		collectFromManagedPolicies(user.AttachedManagedPolicies)
		// Check group policies
		for _, groupName := range user.GroupList {
			if group := state.GetGroupByName(groupName); group != nil {
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

// stmtAllowsAction checks whether a single policy statement is an Allow that
// covers the given action (handling wildcards and NotAction).
func stmtAllowsAction(stmt *types.PolicyStatement, action string) bool {
	if !strings.EqualFold(stmt.Effect, "allow") {
		return false
	}
	if stmt.Action != nil {
		for _, policyAction := range *stmt.Action {
			if iam.MatchesPattern(policyAction, action) {
				return true
			}
		}
		return false
	}
	if stmt.NotAction != nil {
		for _, excluded := range *stmt.NotAction {
			if iam.MatchesPattern(excluded, action) {
				return false
			}
		}
		return true
	}
	return false
}

// resourcePatternsOverlap checks whether any create resource pattern and any use
// resource pattern could refer to the same region+account combination.
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
// to the same region and account.
func arnPatternsCompatible(a, b string) bool {
	if a == "*" || b == "*" {
		return true
	}

	aParts := strings.SplitN(a, ":", 6)
	bParts := strings.SplitN(b, ":", 6)

	if len(aParts) < 5 || len(bParts) < 5 {
		return true
	}

	for i := 0; i < 5; i++ {
		if !iam.MatchesPattern(aParts[i], bParts[i]) && !iam.MatchesPattern(bParts[i], aParts[i]) {
			return false
		}
	}
	return true
}
