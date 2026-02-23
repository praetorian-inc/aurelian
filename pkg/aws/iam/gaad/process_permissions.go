package gaad

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// processUserPermissions collects all identity and boundary statements for a
// user (inline, managed, and group policies) then generates evaluation requests
// for priv-esc actions.
func processUserPermissions(user types.UserDetail, state *AnalyzerState, evalChan chan<- *iam.EvaluationRequest) {
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
func processRolePermissions(role types.RoleDetail, state *AnalyzerState, evalChan chan<- *iam.EvaluationRequest) {
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
func processResourcePolicy(resource output.AWSResource, state *AnalyzerState, evalChan chan<- *iam.EvaluationRequest) {
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
				if err := rc.PopulateDefaultRequestConditionKeys(resourceArn); err != nil {
					slog.Warn("Skipping evaluation: failed to populate request context", "resource", resourceArn, "error", err)
					continue
				}

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

// processAssumeRolePolicies evaluates a role's trust policy (AssumeRolePolicyDocument),
// emitting an EvaluationRequest per principal that the trust policy allows to assume
// the role. These are resource-side evaluations — IdentityStatements is empty.
func processAssumeRolePolicies(role types.RoleDetail, state *AnalyzerState, evalChan chan<- *iam.EvaluationRequest) {
	if role.AssumeRolePolicyDocument.Statement == nil || len(*role.AssumeRolePolicyDocument.Statement) == 0 {
		return
	}

	for _, stmt := range *role.AssumeRolePolicyDocument.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}
		if stmt.Principal == nil {
			slog.Debug(fmt.Sprintf("Skipping statement with nil Principal for role %s", role.Arn))
			continue
		}

		principals := stmt.ExtractPrincipals()
		if len(principals) == 0 {
			slog.Debug(fmt.Sprintf("No principals found in statement for role %s", role.Arn))
			continue
		}

		for _, principal := range principals {
			if principal == "" {
				slog.Debug("Skipping empty principal")
				continue
			}

			roleAccountID, tags := state.GetResourceDetails(role.Arn)

			principalAccountID := roleAccountID
			if principalArn, err := arn.Parse(principal); err == nil {
				if principalArn.AccountID != "" {
					principalAccountID = principalArn.AccountID
				}
			}

			rc := &iam.RequestContext{
				PrincipalArn:     principal,
				ResourceTags:     tags,
				PrincipalAccount: principalAccountID,
				ResourceAccount:  roleAccountID,
				CurrentTime:      time.Now(),
				SecureTransport:  iam.Bool(true),
			}
			if err := rc.PopulateDefaultRequestConditionKeys(role.Arn); err != nil {
				slog.Warn("Skipping assume role evaluation: failed to populate request context", "role", role.Arn, "principal", principal, "error", err)
				continue
			}

			// For service principals (non-ARN), the evaluator requires both
			// identity and resource policy allows for AssumeRole. Service
			// principals don't have identity policies, so we pass the trust
			// policy statements as IdentityStatements (matching old behavior
			// from generateServicePrincipalEvaluations). The statements need
			// Resource set to the role ARN (matching AddResourcePolicies behavior)
			// and OriginArn set for tracing.
			identityStmts := &types.PolicyStatementList{}
			if _, parseErr := arn.Parse(principal); parseErr != nil {
				// Non-ARN principal (service principal like "lambda.amazonaws.com")
				if role.AssumeRolePolicyDocument.Statement != nil {
					stmts := copyStatementsWithOrigin(role.AssumeRolePolicyDocument.Statement, role.Arn)
					for i := range stmts {
						stmts[i].Resource = &types.DynaString{role.Arn}
					}
					identityStmts = &stmts
				}
			}

			evalChan <- &iam.EvaluationRequest{
				Action:             "sts:AssumeRole",
				Resource:           role.Arn,
				IdentityStatements: identityStmts,
				Context:            rc,
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
	state *AnalyzerState,
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
			if err := rc.PopulateDefaultRequestConditionKeys(resource.ARN); err != nil {
				slog.Warn("Skipping evaluation: failed to populate request context", "principal", principalArn, "resource", resource.ARN, "error", err)
				continue
			}

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
