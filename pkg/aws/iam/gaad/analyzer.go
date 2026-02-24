// Package gaad implements the GaadAnalyzer, which evaluates IAM principal
// permissions against cloud resources and organization policies to detect
// privilege escalation paths.
package gaad

import (
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
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
// edges (principal → action → resource) keyed by "principalARN|action|resourceARN".
func (ga *GaadAnalyzer) Analyze(
	gaad *types.AuthorizationAccountDetails,
	orgPolicies *orgpolicies.OrgPolicies,
	resources store.Map[output.AWSResource],
) (store.Map[output.AWSIAMRelationship], error) {
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
	spawnProducers(gaad.Users, &producerWg, func(u types.UserDetail) { processUserPermissions(u, state, evalChan) })
	spawnProducers(gaad.Roles, &producerWg, func(r types.RoleDetail) { processRolePermissions(r, state, evalChan) })
	spawnProducers(resources, &producerWg, func(r output.AWSResource) { processResourcePolicy(r, state, evalChan) })
	spawnProducers(gaad.Roles, &producerWg, func(r types.RoleDetail) { processAssumeRolePolicies(r, state, evalChan) })

	// Drain results concurrently to avoid deadlock when resultChan buffer fills.
	// Workers send to resultChan; if we don't drain it before waiting on evalWg,
	// workers block on send → evalWg.Wait() never returns.
	results := store.NewMap[output.AWSIAMRelationship]()
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for rel := range resultChan {
			results.Set(RelationshipKey(rel), rel)
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
	ga.generateSyntheticPermissions(results, state)

	return results, nil
}

// spawnProducers iterates over a store.Map and launches a goroutine per item,
// tracking completion via the provided WaitGroup.
func spawnProducers[T any](m store.Map[T], wg *sync.WaitGroup, fn func(T)) {
	m.Range(func(_ string, item T) bool {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(item)
		}()
		return true
	})
}

// generateSyntheticPermissions inserts synthetic permission edges that cannot be
// discovered by the evaluator alone (because the target resources don't exist yet
// but could be created by the principal). It mutates results in place.
func (ga *GaadAnalyzer) generateSyntheticPermissions(results store.Map[output.AWSIAMRelationship], state *AnalyzerState) {
	synthesizeCreateThenUsePermissions(results, state)
}

// RelationshipKey returns a composite map key for an AWSIAMRelationship:
// "principalARN|action|resourceARN".
func RelationshipKey(rel output.AWSIAMRelationship) string {
	return rel.Principal.ARN + "|" + rel.Action + "|" + rel.Resource.ARN
}

// buildPolicyData constructs an iam.PolicyData for the evaluator.
// It builds the ResourcePolicies map from AWSResource.ResourcePolicy fields.
// NewPolicyData.AddResourcePolicies() also adds role trust policies from GAAD.
func buildPolicyData(
	gaad *types.AuthorizationAccountDetails,
	orgPolicies *orgpolicies.OrgPolicies,
	resources store.Map[output.AWSResource],
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
