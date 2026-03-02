package publicaccess

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// PublicAccessResult contains the result of a public access evaluation.
type PublicAccessResult struct {
	AWSResource       *output.AWSResource `json:"aws_resource,omitempty"`
	IsPublic          bool                `json:"is_public"`
	NeedsManualTriage bool                `json:"needs_manual_triage,omitempty"`
	AllowedActions    []string            `json:"allowed_actions,omitempty"`
	EvaluationReasons []string            `json:"evaluation_reasons,omitempty"`
}

// evaluateResourcePolicy evaluates whether a resource policy allows public access.
// It tests the policy against multiple evaluation contexts (anonymous access, cross-account access)
// for the actions relevant to the resource type.
//
// The evaluation uses the actual Resource ARNs from the policy statements as evaluation targets.
// This is necessary because the IAM evaluator requires the request resource to match the
// statement's Resource field (e.g., S3 policies use "arn:aws:s3:::bucket/*" for object-level
// actions, not the bucket ARN itself).
func evaluateResourcePolicy(policy *types.Policy, resourceARN, accountID, resourceType string, orgPolicies *orgpolicies.OrgPolicies) (*PublicAccessResult, error) {
	if policy == nil {
		return &PublicAccessResult{IsPublic: false}, nil
	}

	contexts, err := GetEvaluationContexts(resourceType, resourceARN, accountID)
	if err != nil {
		return nil, fmt.Errorf("get evaluation contexts: %w", err)
	}

	if orgPolicies == nil {
		orgPolicies = orgpolicies.NewDefaultOrgPolicies()
	}

	// Extract resource ARNs from policy statements to use as evaluation targets.
	testResources := extractPolicyResources(policy)
	if len(testResources) == 0 {
		testResources = []string{resourceARN}
	}

	result := &PublicAccessResult{}

	for _, testResource := range testResources {
		resourcePolicies := map[string]*types.Policy{
			testResource: policy,
		}

		pd := iam.NewPolicyData(nil, orgPolicies, resourcePolicies, nil)
		policyEvaluator := iam.NewPolicyEvaluator(pd)

		evaluatePolicyContexts(policyEvaluator, testResource, contexts, result)
	}

	return result, nil
}

// hasInconclusiveConditions checks whether any statement evaluation in the policy
// result had inconclusive conditions (missing context keys that couldn't be evaluated).
func evaluatePolicyContexts(
	evaluator *iam.PolicyEvaluator,
	testResource string,
	contexts []EvaluationContext,
	result *PublicAccessResult,
) {
	for _, evalCtx := range contexts {
		req := &iam.EvaluationRequest{
			Action:   evalCtx.Action,
			Resource: testResource,
			Context:  evalCtx.Context,
		}

		evalResult, err := evaluator.Evaluate(req)
		if err != nil {
			result.EvaluationReasons = append(result.EvaluationReasons,
				fmt.Sprintf("error evaluating %s: %v", evalCtx.Action, err))
			continue
		}

		if !evalResult.Allowed {
			continue
		}

		result.IsPublic = true
		result.AllowedActions = appendUnique(result.AllowedActions, evalCtx.Action)
		result.EvaluationReasons = append(result.EvaluationReasons,
			fmt.Sprintf("action %s allowed for principal %s", evalCtx.Action, evalCtx.Context.PrincipalArn))

		if hasInconclusiveConditions(evalResult.PolicyResult) {
			result.NeedsManualTriage = true
			result.EvaluationReasons = append(result.EvaluationReasons,
				fmt.Sprintf("action %s has conditions that could not be fully evaluated", evalCtx.Action))
		}
	}
}

func hasInconclusiveConditions(pr *iam.PolicyResult) bool {
	if pr == nil {
		return false
	}
	for _, evals := range pr.Evaluations {
		for _, eval := range evals {
			if eval.ConditionEvaluation != nil && eval.ConditionEvaluation.Result == iam.ConditionInconclusive {
				return true
			}
		}
	}
	return false
}

// extractPolicyResources extracts unique resource ARNs from policy statements.
func extractPolicyResources(policy *types.Policy) []string {
	if policy == nil || policy.Statement == nil {
		return nil
	}

	seen := make(map[string]bool)
	var resources []string
	for _, stmt := range *policy.Statement {
		if stmt.Resource != nil {
			for _, r := range *stmt.Resource {
				if !seen[r] {
					seen[r] = true
					resources = append(resources, r)
				}
			}
		}
	}
	return resources
}

func appendUnique(slice []string, item string) []string {
	for _, existing := range slice {
		if existing == item {
			return slice
		}
	}
	return append(slice, item)
}
