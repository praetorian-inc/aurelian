package gaad

import (
	"time"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// processUserPermissions collects all identity and boundary statements for a
// user (inline, managed, and group policies) then generates evaluation requests
// for priv-esc actions.
func processUserPermissions(user types.UserDetail, state AnalyzerState, evalChan chan<- *iam.EvaluationRequest) {
	// Inline policies
	identityStatements := collectInlineStatements(user.UserPolicyList, user.Arn)

	// Managed policies
	identityStatements = append(identityStatements, collectManagedPolicyStatements(state, user.AttachedManagedPolicies)...)

	// Permissions boundary
	boundaryStatements := collectBoundaryStatements(state, user.PermissionsBoundary)

	// Group policies (inline + managed)
	for _, groupName := range user.GroupList {
		group := state.GetGroupByName(groupName)
		if group == nil {
			continue
		}
		identityStatements = append(identityStatements, collectInlineStatements(group.GroupPolicyList, group.Arn)...)
		identityStatements = append(identityStatements, collectManagedPolicyStatements(state, group.AttachedManagedPolicies)...)
	}

	generatePrincipalEvalRequests(user.Arn, identityStatements, boundaryStatements, state, evalChan)
}

// processRolePermissions collects all identity and boundary statements for a
// role (inline and managed policies) then generates evaluation requests for
// priv-esc actions.
//
// Unlike the old implementation, this does NOT mutate the ARPD for AssumeRole
// actions (that was a bug) — trust policy evaluation is handled separately by
// processAssumeRolePolicies (step 4f).
func processRolePermissions(role types.RoleDetail, state AnalyzerState, evalChan chan<- *iam.EvaluationRequest) {
	// Inline policies
	identityStatements := collectInlineStatements(role.RolePolicyList, role.Arn)

	// Managed policies
	identityStatements = append(identityStatements, collectManagedPolicyStatements(state, role.AttachedManagedPolicies)...)

	// Permissions boundary
	boundaryStatements := collectBoundaryStatements(state, role.PermissionsBoundary)

	generatePrincipalEvalRequests(role.Arn, identityStatements, boundaryStatements, state, evalChan)
}

// processResourcePolicy processes a single resource's policy,
// emitting an EvaluationRequest for each (service principal, priv-esc action)
// pair found in the policy statements.
//
// Unlike the old implementation, this emits ALL matching pairs per resource
// policy, fixing the first-match-only bug.
func processResourcePolicy(resource output.AWSResource, state AnalyzerState, evalChan chan<- *iam.EvaluationRequest) {
	policy := resource.ResourcePolicy
	if policy == nil || policy.Statement == nil {
		return
	}

	resourceArn := resource.ARN
	stmtsCopied := false
	var stmts types.PolicyStatementList

	for _, stmt := range *policy.Statement {
		if stmt.Principal == nil || stmt.Principal.Service == nil {
			continue
		}
		if stmt.Action == nil {
			continue
		}
		for _, service := range *stmt.Principal.Service {
			for _, action := range *stmt.Action {
				if !iam.IsPrivEscAction(action) {
					continue
				}

				// Lazy copy: only allocate when we find a match
				if !stmtsCopied {
					stmts = copyStatementsWithOrigin(policy.Statement, resourceArn)
					stmtsCopied = true
				}

				accountID, tags := state.GetResourceDetails(resourceArn)
				rc := &iam.RequestContext{
					PrincipalArn:     service,
					ResourceTags:     tags,
					PrincipalAccount: accountID,
					CurrentTime:      time.Now(),
				}
				rc.PopulateDefaultRequestConditionKeys(resourceArn)

				evalChan <- &iam.EvaluationRequest{
					Action:             action,
					Resource:           resourceArn,
					IdentityStatements: &stmts,
					Context:            rc,
				}
			}
		}
	}
}

// generatePrincipalEvalRequests is the shared core for user and role processing.
// It extracts priv-esc actions from identity statements, matches them against
// resources, and sends EvaluationRequests to evalChan.
func generatePrincipalEvalRequests(
	principalArn string,
	identityStatements types.PolicyStatementList,
	boundaryStatements types.PolicyStatementList,
	state AnalyzerState,
	evalChan chan<- *iam.EvaluationRequest,
) {
	allActions := state.ExtractActions(&identityStatements)

	for _, action := range allActions {
		if !iam.IsPrivEscAction(action) {
			continue
		}

		for _, resource := range state.GetResourcesByAction(iam.Action(action)) {
			accountID, tags := state.GetResourceDetails(resource.ARN)

			rc := &iam.RequestContext{
				PrincipalArn:     principalArn,
				ResourceTags:     tags,
				PrincipalAccount: accountID,
				CurrentTime:      time.Now(),
			}
			rc.PopulateDefaultRequestConditionKeys(resource.ARN)

			evalChan <- &iam.EvaluationRequest{
				Action:             action,
				Resource:           resource.ARN,
				IdentityStatements: &identityStatements,
				BoundaryStatements: &boundaryStatements,
				Context:            rc,
			}
		}
	}
}
