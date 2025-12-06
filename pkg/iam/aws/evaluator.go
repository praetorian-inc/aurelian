package aws

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/nebula/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type PolicyData struct {
	Gaad             *types.Gaad
	OrgPolicies      *orgpolicies.OrgPolicies
	ResourcePolicies map[string]*types.Policy
	Resources        *[]types.EnrichedResourceDescription
}

func NewPolicyData(gaad *types.Gaad, orgPolicies *orgpolicies.OrgPolicies, resourcePolicies map[string]*types.Policy, resources *[]types.EnrichedResourceDescription) *PolicyData {
	if resourcePolicies == nil {
		resourcePolicies = make(map[string]*types.Policy, 0)
	}

	pd := &PolicyData{
		Gaad:             gaad,
		OrgPolicies:      orgPolicies,
		ResourcePolicies: resourcePolicies,
		Resources:        resources,
	}

	pd.AddResourcePolicies()
	return pd
}

func (pd *PolicyData) AddResourcePolicies() {
	// Create resource polices from role assume role policies
	if pd.Gaad != nil {
		for _, role := range pd.Gaad.RoleDetailList {
			if role.AssumeRolePolicyDocument.Statement != nil {
				// Create copy of statements to avoid modifying original
				stmtCopy := make(types.PolicyStatementList, len(*role.AssumeRolePolicyDocument.Statement))
				copy(stmtCopy, *role.AssumeRolePolicyDocument.Statement)

				// Set resource and origin for each statement
				for i := range stmtCopy {
					stmtCopy[i].Resource = &types.DynaString{role.Arn}
					stmtCopy[i].OriginArn = fmt.Sprintf("%s/AssumeRolePolicyDocument", role.Arn)
				}

				// Add to resource policies map
				pd.ResourcePolicies[role.Arn] = &types.Policy{
					Statement: &stmtCopy,
				}
			}
		}
	}
}

// EvaluationType identifies the type of policy evaluation
type EvaluationType string

const (
	EvalTypeIdentity     EvaluationType = "Identity"
	EvalTypeResource     EvaluationType = "Resource"
	EvalTypeSCP          EvaluationType = "SCP"
	EvalTypePermBoundary EvaluationType = "PermissionBoundary"
	EvalTypeRCP          EvaluationType = "RCP"
)

// PolicyResult captures all statement evaluations organized by policy type
type PolicyResult struct {
	Evaluations map[EvaluationType][]*StatementEvaluation
}

// NewPolicyResult creates a new PolicyResult with initialized map
func NewPolicyResult() *PolicyResult {
	return &PolicyResult{
		Evaluations: make(map[EvaluationType][]*StatementEvaluation),
	}
}

// AddEvaluation adds statement evaluations for a specific policy type
func (pr *PolicyResult) AddEvaluation(evalType EvaluationType, evals []*StatementEvaluation) {
	pr.Evaluations[evalType] = evals
}

// HasDeny checks if any policy type has an explicit deny
func (pr *PolicyResult) HasDeny() bool {
	for _, evals := range pr.Evaluations {
		for _, eval := range evals {
			if eval.ExplicitDeny {
				return true
			}
		}
	}
	return false
}

// hasAllow checks if any policy type has an explicit allow
func (pr *PolicyResult) hasAllow() bool {
	for _, evals := range pr.Evaluations {
		for _, eval := range evals {
			if eval.ExplicitAllow {
				return true
			}
		}
	}
	return false
}

// hasTypeAllow checks if a specific policy type has an explicit allow
func (pr *PolicyResult) hasTypeAllow(evalType EvaluationType) bool {
	if evals, exists := pr.Evaluations[evalType]; exists {
		for _, eval := range evals {
			if eval.ExplicitAllow {
				return true
			}
		}
	}
	return false
}

// allPoliciesHaveAllow checks if all policies of a specific type have an explicit allow
// This is used for special cases like SCPs
func (pr *PolicyResult) allPoliciesHaveAllow(evalType EvaluationType) bool {
	if evals, exists := pr.Evaluations[evalType]; exists {
		for _, eval := range evals {
			if !eval.ExplicitAllow {
				return false
			}
		}
	}
	return true
}

// hasTypeDeny checks if a specific policy type has an explicit deny
// func (pr *PolicyResult) hasTypeDeny(evalType EvaluationType) bool {
// 	if evals, exists := pr.Evaluations[evalType]; exists {
// 		for _, eval := range evals {
// 			if eval.ExplicitDeny {
// 				return true
// 			}
// 		}
// 	}
// 	return false
// }

// IsAllowed determines if the overall policy evaluations result in an allow
func (pr *PolicyResult) IsAllowed() bool {
	if pr.HasDeny() {
		return false
	}
	return pr.hasAllow()
}

// EvaluationRequest contains all inputs needed for policy evaluation
type EvaluationRequest struct {
	// Core request details
	Action   string          // Requested action (e.g. s3:GetObject)
	Resource string          // Target resource ARN
	Context  *RequestContext // Request context for condition evaluation

	// Identity-based policies
	IdentityStatements *types.PolicyStatementList // Identity policy statements
	BoundaryStatements *types.PolicyStatementList // Optional permission boundary
}

func (er *EvaluationRequest) String() string {
	return fmt.Sprintf("Principal: %s, Action: %s, Resource: %s, Context: %v", er.Context.PrincipalArn, er.Action, er.Resource, er.Context)
}

// EvaluationResult represents the final evaluation outcome
type EvaluationResult struct {
	Allowed            bool
	PolicyResult       *PolicyResult
	EvaluationDetails  string
	CrossAccountAccess bool
	Action             Action
	// SSM-specific fields for tracking document restrictions
	SSMDocumentRestrictions []string // List of allowed SSM document ARNs/patterns (e.g., ["arn:aws:ssm:*:*:document/AWS-RunShellScript", "*"])
}

func (er *EvaluationResult) String() string {
	jsonResult, err := json.MarshalIndent(er, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling EvaluationResult to JSON: %v\n", err)
		return ""
	}
	return string(jsonResult)
}

func (er *EvaluationResult) HasInconclusiveCondition() bool {
	if er.PolicyResult == nil {
		return false
	}

	// Iterate through all evaluation types
	for _, statements := range er.PolicyResult.Evaluations {
		for _, statement := range statements {
			if statement.ConditionEvaluation != nil &&
				statement.ConditionEvaluation.Result == ConditionInconclusive {
				return true
			}
		}
	}

	return false
}

// PolicyEvaluator handles AWS IAM policy evaluation
type PolicyEvaluator struct {
	policyData *PolicyData
}

// NewPolicyEvaluator creates a new policy evaluator instance
func NewPolicyEvaluator(pd *PolicyData) *PolicyEvaluator {
	if pd.OrgPolicies == nil {
		// Default to full AWS access if no SCP is present
		pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
	}
	return &PolicyEvaluator{
		policyData: pd,
	}
}

// policyToStatementList converts a Policy to a PolicyStatementList
func policyToStatementList(policy *types.Policy) *types.PolicyStatementList {
	if policy == nil || policy.Statement == nil {
		return nil
	}
	return policy.Statement
}

// Evaluate performs the full policy evaluation
func (e *PolicyEvaluator) Evaluate(req *EvaluationRequest) (*EvaluationResult, error) {
	// First validate that the action is valid for the resource type
	if !IsValidActionForResource(req.Action, req.Resource) {
		return &EvaluationResult{
			Allowed:           false,
			PolicyResult:      NewPolicyResult(),
			EvaluationDetails: fmt.Sprintf("Action %s is not valid for resource %s", req.Action, req.Resource),
		}, nil
	}

	result := &EvaluationResult{
		PolicyResult: NewPolicyResult(),
		Action:       Action(req.Action),
	}

	// 1. First check all policy types for explicit denies
	denyResult, err := e.checkExplicitDenies(req)
	if err != nil {
		return nil, err
	}
	if !denyResult.Allowed {
		// Copy over any evaluations that were done during deny checking
		for evalType, evals := range denyResult.PolicyResult.Evaluations {
			result.PolicyResult.AddEvaluation(evalType, evals)
		}
		return denyResult, nil
	}

	// 2a. Evaluate parent RCPs if present
	parentRcps := e.policyData.OrgPolicies.GetMergedParentRcpsForTarget(req.Context.ResourceAccount)
	if len(parentRcps) > 0 {
		// Check that each parent RCP group has at least one allow statement
		for parentID, policyStatements := range parentRcps {
			parentEvals, err := e.evaluatePolicyType(req.Action, req.Resource, req.Context,
				policyStatements, EvalTypeRCP)
			if err != nil {
				return nil, err
			}

			// Add all evaluations to the result
			result.PolicyResult.AddEvaluation(EvalTypeRCP, parentEvals)

			// Check if this parent group has at least one allow
			hasParentAllow := false
			for _, eval := range parentEvals {
				if eval.ExplicitAllow {
					hasParentAllow = true
					break
				}
			}

			// If any parent group doesn't have an allow, deny the request
			if !hasParentAllow {
				result.Allowed = false
				result.EvaluationDetails = fmt.Sprintf("No explicit allow in parent RCP from %s", parentID)
				return result, nil
			}
		}
	}

	// 2b. Evaluate directly attached RCPs if present
	rcps := e.policyData.OrgPolicies.GetDirectRcpStatementsForTarget(req.Context.ResourceAccount)
	if rcps != nil && len(*rcps) > 0 {
		rcpEvals, err := e.evaluatePolicyType(req.Action, req.Resource, req.Context,
			rcps, EvalTypeRCP)
		if err != nil {
			return nil, err
		}
		result.PolicyResult.AddEvaluation(EvalTypeRCP, rcpEvals)
		if !result.PolicyResult.hasTypeAllow(EvalTypeRCP) {
			result.Allowed = false
			result.EvaluationDetails = "Denied by RCP"
			return result, nil
		}
	}

	// 3a. Evaluate parent SCPs if present
	parentScps := e.policyData.OrgPolicies.GetMergedParentScpsForTarget(req.Context.ResourceAccount)
	if len(parentScps) > 0 {
		// Check that each parent SCP group has at least one allow statement
		for parentID, policyStatements := range parentScps {
			parentEvals, err := e.evaluatePolicyType(req.Action, req.Resource, req.Context,
				policyStatements, EvalTypeSCP)
			if err != nil {
				return nil, err
			}

			// Add all evaluations to the result
			result.PolicyResult.AddEvaluation(EvalTypeSCP, parentEvals)

			// Check if this parent group has at least one allow
			hasParentAllow := false
			for _, eval := range parentEvals {
				if eval.ExplicitAllow {
					hasParentAllow = true
					break
				}
			}

			// If any parent group doesn't have an allow, deny the request
			if !hasParentAllow {
				result.Allowed = false
				result.EvaluationDetails = fmt.Sprintf("No explicit allow in parent SCP from %s", parentID)
				return result, nil
			}
		}
	}

	// 3b. Evaluate SCPs if present (these are always enforced)
	scps := e.policyData.OrgPolicies.GetDirectScpStatementsForTarget(req.Context.ResourceAccount)
	if scps != nil && len(*scps) > 0 {
		scpEvals, err := e.evaluatePolicyType(req.Action, req.Resource, req.Context,
			scps, EvalTypeSCP)
		if err != nil {
			return nil, err
		}

		result.PolicyResult.AddEvaluation(EvalTypeSCP, scpEvals)
		if !result.PolicyResult.hasTypeAllow(EvalTypeSCP) {
			result.Allowed = false
			result.EvaluationDetails = "Denied by SCP"
			return result, nil
		}
	}

	// 4. Evaluate permission boundary if present
	if req.BoundaryStatements != nil && len(*req.BoundaryStatements) > 0 {
		boundaryEvals, err := e.evaluatePolicyType(req.Action, req.Resource, req.Context,
			req.BoundaryStatements, EvalTypePermBoundary)
		if err != nil {
			return nil, err
		}
		result.PolicyResult.AddEvaluation(EvalTypePermBoundary, boundaryEvals)
		if !result.PolicyResult.hasTypeAllow(EvalTypePermBoundary) {
			result.Allowed = false
			result.EvaluationDetails = "Denied by permission boundary"
			return result, nil
		}
	}

	// 5. Check if this is a cross-account request
	result.CrossAccountAccess = e.isCrossAccountRequest(req.Resource, req.Context)

	// 6. Evaluate resource-based policy if present
	resourceAllowed := false
	explicitPrincipalAllow := false

	if e.policyData.ResourcePolicies != nil {
		if resourcePolicy, exists := e.policyData.ResourcePolicies[req.Resource]; exists {
			resourceStatements := policyToStatementList(resourcePolicy)
			resourceEvals, err := e.evaluatePolicyType(req.Action, req.Resource, req.Context,
				resourceStatements, EvalTypeResource)
			if err != nil {
				return nil, err
			}
			result.PolicyResult.AddEvaluation(EvalTypeResource, resourceEvals)
			resourceAllowed = result.PolicyResult.hasTypeAllow(EvalTypeResource)

			// Check if principal is explicitly allowed
			explicitPrincipalAllow = e.hasExplicitPrincipalAllow(resourceStatements, req.Context.PrincipalArn)

			if resourceAllowed && explicitPrincipalAllow && result.PolicyResult.IsAllowed() {
				result.Allowed = true
				result.EvaluationDetails = "Explicitly allowed by resource policy"
				return result, nil
			}
		}
	}

	// 7. Evaluate identity-based policy
	if req.IdentityStatements != nil && len(*req.IdentityStatements) > 0 {
		identityEvals, err := e.evaluatePolicyType(req.Action, req.Resource, req.Context,
			req.IdentityStatements, EvalTypeIdentity)
		if err != nil {
			return nil, err
		}
		result.PolicyResult.AddEvaluation(EvalTypeIdentity, identityEvals)
	}

	// 8. Make final determination based on cross-account status, policy evaluations,
	//    and special handling for assume role operations

	// Check if this is an AssumeRole operation on an IAM role
	isAssumeRoleOperation := strings.HasPrefix(req.Action, "sts:AssumeRole") &&
		strings.Contains(req.Resource, ":role/")

	if result.CrossAccountAccess {
		if isAssumeRoleOperation {
			// Special case: For cross-account assume role, the trust policy (resource policy)
			// must allow the principal, and the principal needs sts:AssumeRole permission
			result.Allowed = result.PolicyResult.hasTypeAllow(EvalTypeIdentity) && resourceAllowed
			result.EvaluationDetails = "Cross-account assume role access"
		} else {
			// Normal cross-account access requires both identity and resource policy allows
			result.Allowed = result.PolicyResult.hasTypeAllow(EvalTypeIdentity) && resourceAllowed
			result.EvaluationDetails = "Cross-account access"
		}
	} else {
		// Same account access allows if:
		// - Principal is explicitly named in resource policy, OR
		// - Either identity or resource policy allows (when not explicitly named)
		result.Allowed = explicitPrincipalAllow && result.PolicyResult.hasTypeAllow(EvalTypeResource) ||
			result.PolicyResult.hasTypeAllow(EvalTypeIdentity)
		result.EvaluationDetails = "Same-account access"
	}

	// Extract SSM document restrictions for relevant actions
	if req.IdentityStatements != nil {
		result.SSMDocumentRestrictions = extractSSMDocumentRestrictions(req.Action, req.IdentityStatements)
	}

	return result, nil
}

func (e *PolicyEvaluator) evaluatePolicyType(action, resource string, ctx *RequestContext, statements *types.PolicyStatementList, evalType EvaluationType) ([]*StatementEvaluation, error) {
	if statements == nil {
		return nil, nil
	}

	evals := make([]*StatementEvaluation, 0)

	// Skip SCP evaluation for service-linked roles
	if evalType == EvalTypeSCP && ctx.IsServiceLinkedRole() {
		eval := &StatementEvaluation{
			ExplicitAllow:    true,
			ExplicitDeny:     false,
			ImplicitDeny:     false,
			MatchedAction:    true,
			MatchedResource:  true,
			MatchedPrincipal: true,
			Origin:           "SCP - Service-Linked Role Bypass",
		}
		evals = append(evals, eval)
		return evals, nil
	}

	for _, statement := range *statements {
		eval := evaluateStatement(&statement, action, resource, ctx)
		evals = append(evals, eval)
	}

	return evals, nil
}

func (e *PolicyEvaluator) checkExplicitDenies(req *EvaluationRequest) (*EvaluationResult, error) {
	result := &EvaluationResult{
		PolicyResult: NewPolicyResult(),
	}

	// Helper function to check a policy type for explicit denies
	checkPolicyDenies := func(statements *types.PolicyStatementList, evalType EvaluationType) ([]*StatementEvaluation, error) {
		if statements == nil {
			return nil, nil
		}

		evals, err := e.evaluatePolicyType(req.Action, req.Resource, req.Context, statements, evalType)
		if err != nil {
			return nil, err
		}

		return evals, nil
	}

	// Check each policy type in order of precedence
	policies := []struct {
		statements *types.PolicyStatementList
		evalType   EvaluationType
	}{
		{e.policyData.OrgPolicies.GetAllScpPoliciesForTarget(req.Context.ResourceAccount), EvalTypeSCP},
		{e.policyData.OrgPolicies.GetAllRcpPoliciesForTarget(req.Context.ResourceAccount), EvalTypeRCP},
		{req.BoundaryStatements, EvalTypePermBoundary},
		{req.IdentityStatements, EvalTypeIdentity},
	}

	for _, policy := range policies {
		evals, err := checkPolicyDenies(policy.statements, policy.evalType)
		if err != nil {
			return nil, err
		}
		if evals != nil {
			result.PolicyResult.AddEvaluation(policy.evalType, evals)
			for _, eval := range evals {
				if eval.ExplicitDeny {
					result.Allowed = false
					result.EvaluationDetails = fmt.Sprintf("Explicitly denied by %s", policy.evalType)
					return result, nil
				}
			}
		}
	}

	// Check resource-based policies last
	if resourcePolicy, exists := e.policyData.ResourcePolicies[req.Resource]; exists {
		resourceStatements := policyToStatementList(resourcePolicy)
		evals, err := checkPolicyDenies(resourceStatements, EvalTypeResource)
		if err != nil {
			return nil, err
		}
		if evals != nil {
			result.PolicyResult.AddEvaluation(EvalTypeResource, evals)
			for _, eval := range evals {
				if eval.ExplicitDeny {
					result.Allowed = false
					result.EvaluationDetails = "Explicitly denied by resource-based policy"
					return result, nil
				}
			}
		}
	}

	// If we get here, no explicit denies were found
	result.Allowed = true
	return result, nil
}

// isCrossAccountRequest determines if a request is cross-account by comparing the principal's account
// with the resource's account. It handles wildcards and global services by assuming the resource
// is in the same account as the principal in those cases.
func (e *PolicyEvaluator) isCrossAccountRequest(resourceArn string, ctx *RequestContext) bool {
	// Parse principal ARN
	principalAcct, err := arn.Parse(ctx.PrincipalArn)
	if err != nil {
		return false // If we can't parse principal ARN, assume same account for safety
	}

	// Parse resource ARN
	resourceAcct, err := arn.Parse(resourceArn)
	if err != nil {
		return false // If we can't parse resource ARN, assume same account for safety
	}

	// Handle special cases
	// If resource account contains wildcard or is empty, assume same account
	// Empty account ID is used for global services
	if resourceAcct.AccountID == "*" || resourceAcct.AccountID == "" {
		return false
	}

	// Compare account IDs
	return principalAcct.AccountID != resourceAcct.AccountID
}

func (e *PolicyEvaluator) hasExplicitPrincipalAllow(statements *types.PolicyStatementList, principalArn string) bool {
	for _, statement := range *statements {
		// Skip Deny statements and statements without Principal
		if strings.EqualFold(statement.Effect, "Deny") || statement.Principal == nil {
			continue
		}

		// Check AWS principals
		if statement.Principal.AWS != nil {
			for _, allowedPrincipal := range *statement.Principal.AWS {
				// Direct ARN match
				if allowedPrincipal == principalArn {
					return true
				}
				// Account-level wildcard that matches principal's account
				if allowedPrincipal == "*" ||
					(strings.HasSuffix(allowedPrincipal, ":root") &&
						strings.HasPrefix(principalArn, strings.TrimSuffix(allowedPrincipal, "root"))) {
					return true
				}
				// Wildcard in same account
				if strings.Contains(allowedPrincipal, "*") &&
					strings.HasPrefix(allowedPrincipal, strings.Split(principalArn, ":user/")[0]) {
					return true
				}
			}
		}

		// Check service principals
		if statement.Principal.Service != nil {
			for _, allowedService := range *statement.Principal.Service {
				if allowedService == principalArn {
					return true
				}
			}
		}
	}
	return false
}

type StatementEvaluation struct {
	ExplicitAllow       bool           // Statement matched and explicitly allows
	ExplicitDeny        bool           // Statement matched and explicitly denies
	ImplicitDeny        bool           // Default deny or criteria didn't match
	MatchedAction       bool           // For debugging - did action/notAction match
	MatchedResource     bool           // For debugging - did resource/notResource match
	MatchedPrincipal    bool           // For debugging - did principal match
	ConditionEvaluation *ConditionEval // Detailed condition evaluation results
	Origin              string
}

func (eval *StatementEvaluation) IsAllowed() bool {
	return eval.ExplicitAllow && !eval.ExplicitDeny && !eval.ImplicitDeny
}

// allPoliciesAllow checks if all policies of a specific type have an explicit allow
// This is used for special cases like SCPs and RCPs
func allPoliciesAllow(evals []*StatementEvaluation) bool {
	for _, eval := range evals {
		if !eval.IsAllowed() {
			return false
		}
	}
	return true
}

// extractSSMDocumentRestrictions extracts the allowed SSM document ARNs/patterns from policy statements
// for SSM actions that require document resources (e.g., ssm:SendCommand, ssm:StartAutomationExecution)
func extractSSMDocumentRestrictions(action string, statements *types.PolicyStatementList) []string {
	// Check if this is an SSM action that requires document restrictions
	if !strings.HasPrefix(strings.ToLower(action), "ssm:") {
		return nil
	}

	// Actions that require document resource checks
	documentActions := map[string]bool{
		"ssm:sendcommand":             true,
		"ssm:startautomationexecution": true,
	}

	if !documentActions[strings.ToLower(action)] {
		return nil
	}

	if statements == nil {
		return nil
	}

	documentRestrictions := []string{}

	// Iterate through all statements to find document resource restrictions
	for _, stmt := range *statements {
		// Only consider Allow statements
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}

		// Check if this statement grants the requested action
		actionMatches := false
		if stmt.Action != nil {
			for _, stmtAction := range *stmt.Action {
				if matchesPattern(stmtAction, action) {
					actionMatches = true
					break
				}
			}
		}

		if !actionMatches {
			continue
		}

		// Extract document resources from the Resource field
		if stmt.Resource != nil {
			for _, resource := range *stmt.Resource {
				// Check if this is an SSM document ARN
				if strings.Contains(resource, ":document/") ||
				   strings.Contains(resource, ":automation-definition/") {
					documentRestrictions = append(documentRestrictions, resource)
				} else if resource == "*" {
					// Wildcard means any document is allowed
					documentRestrictions = append(documentRestrictions, "*")
				}
			}
		}
	}

	// If no specific documents found but action is allowed, might mean unrestricted
	// This will be empty array which we can interpret as "checked but no explicit document restriction"
	return documentRestrictions
}
