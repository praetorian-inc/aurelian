// Package gaad implements the GaadAnalyzer, which evaluates IAM principal
// permissions against cloud resources and organization policies to detect
// privilege escalation paths.
package gaad

import (
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/cache"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// GaadAnalyzer analyzes GAAD data, cloud resources, and org policies
// to determine principal→permission→resource paths.
type GaadAnalyzer struct{}

// NewGaadAnalyzer creates a new GaadAnalyzer.
func NewGaadAnalyzer() *GaadAnalyzer {
	return &GaadAnalyzer{}
}

// Analyze evaluates all principal permissions against resources and org policies,
// detecting privilege escalation paths. Returns the set of allowed permission
// edges (principal → action → resource).
func (ga *GaadAnalyzer) Analyze(
	gaad *types.AuthorizationAccountDetails,
	orgPolicies *orgpolicies.OrgPolicies,
	resources cache.Map[output.AWSResource],
) ([]output.AWSIAMRelationship, error) {
	state := NewAnalyzerState(gaad, orgPolicies, resources)
	policyData := buildPolicyData(gaad, orgPolicies, resources)
	evaluator := iam.NewPolicyEvaluator(policyData)

	evalChan := make(chan *iam.EvaluationRequest, 1000)
	resultChan := make(chan output.AWSIAMRelationship, 1000)

	// Start evaluation workers
	var evalWg sync.WaitGroup
	startEvaluationWorkers(evalChan, resultChan, evaluator, state, &evalWg)

	// Launch producers
	var producerWg sync.WaitGroup
	gaad.Users.Range(func(_ string, user types.UserDetail) bool {
		producerWg.Add(1)
		go func(u types.UserDetail) {
			defer producerWg.Done()
			processUserPermissions(u, state, evalChan)
		}(user)
		return true
	})
	gaad.Roles.Range(func(_ string, role types.RoleDetail) bool {
		producerWg.Add(1)
		go func(r types.RoleDetail) {
			defer producerWg.Done()
			processRolePermissions(r, state, evalChan)
		}(role)
		return true
	})

	resources.Range(func(_ string, resource output.AWSResource) bool {
		producerWg.Add(1)
		go func(r output.AWSResource) {
			defer producerWg.Done()
			processResourcePolicy(r, state, evalChan)
		}(resource)
		return true
	})

	gaad.Roles.Range(func(_ string, role types.RoleDetail) bool {
		producerWg.Add(1)
		go func(r types.RoleDetail) {
			defer producerWg.Done()
			processAssumeRolePolicies(r, state, evalChan)
		}(role)
		return true
	})

	// Drain results concurrently to avoid deadlock when resultChan buffer fills.
	// Workers send to resultChan; if we don't drain it before waiting on evalWg,
	// workers block on send → evalWg.Wait() never returns.
	var results []output.AWSIAMRelationship
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for rel := range resultChan {
			results = append(results, rel)
		}
	}()

	// Wait for all producers, then close eval channel
	producerWg.Wait()
	close(evalChan)

	// Wait for all eval workers, then close result channel
	evalWg.Wait()
	close(resultChan)

	// Wait for collector to finish draining
	collectWg.Wait()

	// Add synthetic permission edges for attack patterns the evaluator can't discover
	results = ga.generateSyntheticPermissions(results, state)

	return results, nil
}

// generateSyntheticPermissions appends synthetic permission edges that cannot be
// discovered by the evaluator alone (because the target resources don't exist yet
// but could be created by the principal). Additional synthetic techniques can be
// added here in the future.
func (ga *GaadAnalyzer) generateSyntheticPermissions(results []output.AWSIAMRelationship, state *AnalyzerState) []output.AWSIAMRelationship {
	return synthesizeCreateThenUsePermissions(results, state)
}

// buildPolicyData constructs an iam.PolicyData for the evaluator.
// It builds the ResourcePolicies map from AWSResource.ResourcePolicy fields.
// NewPolicyData.AddResourcePolicies() also adds role trust policies from GAAD.
func buildPolicyData(
	gaad *types.AuthorizationAccountDetails,
	orgPolicies *orgpolicies.OrgPolicies,
	resources cache.Map[output.AWSResource],
) *iam.PolicyData {
	resourcePolicies := make(map[string]*types.Policy)
	resources.Range(func(_ string, r output.AWSResource) bool {
		if r.ResourcePolicy != nil {
			resourcePolicies[r.ARN] = r.ResourcePolicy
		}
		return true
	})
	return iam.NewPolicyData(gaad, orgPolicies, resourcePolicies, nil)
}
