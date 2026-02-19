// Package gaad implements the GaadAnalyzer, which evaluates IAM principal
// permissions against cloud resources and organization policies to detect
// privilege escalation paths.
package gaad

import (
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
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
	resources []output.AWSResource,
) ([]output.AWSIAMRelationship, error) {
	state := NewAnalyzerMemoryState(gaad, orgPolicies, resources)
	policyData := buildPolicyData(gaad, orgPolicies, resources)
	evaluator := iam.NewPolicyEvaluator(policyData)

	// Buffered channel for evaluation requests from producers
	evalChan := make(chan *iam.EvaluationRequest, 1000)
	// Channel for allowed relationships from eval workers
	resultChan := make(chan output.AWSIAMRelationship, 1000)

	// Start evaluation workers
	var evalWg sync.WaitGroup
	startEvaluationWorkers(evalChan, resultChan, evaluator, state, &evalWg)

	// Launch producers
	var producerWg sync.WaitGroup
	for _, user := range gaad.UserDetailList {
		producerWg.Add(1)
		go func(u types.UserDetail) {
			defer producerWg.Done()
			processUserPermissions(u, state, evalChan)
		}(user)
	}
	for _, role := range gaad.RoleDetailList {
		producerWg.Add(1)
		go func(r types.RoleDetail) {
			defer producerWg.Done()
			processRolePermissions(r, state, evalChan)
		}(role)
	}

	// TODO (4e): generateServicePrincipalEvaluations
	// TODO (4f): processAssumeRolePolicies

	// Wait for all producers, then close eval channel
	producerWg.Wait()
	close(evalChan)

	// Wait for all eval workers, then close result channel
	evalWg.Wait()
	close(resultChan)

	// Collect results
	var results []output.AWSIAMRelationship
	for rel := range resultChan {
		results = append(results, rel)
	}

	// TODO (4g): applyCreateThenUseEdges

	return results, nil
}

// buildPolicyData constructs an iam.PolicyData for the evaluator.
// It builds the ResourcePolicies map from AWSResource.ResourcePolicy fields.
// NewPolicyData.AddResourcePolicies() also adds role trust policies from GAAD.
func buildPolicyData(
	gaad *types.AuthorizationAccountDetails,
	orgPolicies *orgpolicies.OrgPolicies,
	resources []output.AWSResource,
) *iam.PolicyData {
	resourcePolicies := make(map[string]*types.Policy)
	for i := range resources {
		if resources[i].ResourcePolicy != nil {
			resourcePolicies[resources[i].ARN] = resources[i].ResourcePolicy
		}
	}
	return iam.NewPolicyData(gaad, orgPolicies, resourcePolicies, nil)
}

// startEvaluationWorkers launches a pool of goroutines that consume
// EvaluationRequests, evaluate them, and send allowed results to resultChan.
func startEvaluationWorkers(
	evalChan <-chan *iam.EvaluationRequest,
	resultChan chan<- output.AWSIAMRelationship,
	evaluator *iam.PolicyEvaluator,
	state AnalyzerState,
	wg *sync.WaitGroup,
) {
	numWorkers := runtime.NumCPU() * 3
	slog.Debug(fmt.Sprintf("Starting %d evaluation workers", numWorkers))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range evalChan {
				result, err := evaluator.Evaluate(req)
				if err != nil {
					slog.Error("Error evaluating permissions",
						"principal", req.Context.PrincipalArn,
						"resource", req.Resource,
						"action", req.Action,
						"error", err)
					continue
				}

				if !result.Allowed {
					continue
				}

				// Build the relationship for allowed evaluations
				principal := buildPrincipal(req.Context.PrincipalArn, state)
				resource := state.GetResource(req.Resource)
				if resource == nil {
					slog.Debug("Resource not found for allowed eval",
						"resource", req.Resource)
					continue
				}

				resultChan <- output.AWSIAMRelationship{
					Principal: principal,
					Resource:  *resource,
					Action:    req.Action,
				}
			}
		}()
	}
}

// buildPrincipal looks up a principal ARN in the state and wraps it as an
// AWSIAMResource. If not found, returns a minimal AWSIAMResource with just
// the ARN populated.
func buildPrincipal(principalArn string, state AnalyzerState) output.AWSIAMResource {
	if r := state.GetResource(principalArn); r != nil {
		return output.FromAWSResource(*r)
	}
	return output.AWSIAMResource{
		AWSResource: output.AWSResource{
			Platform:   "aws",
			ARN:        principalArn,
			ResourceID: principalArn,
		},
	}
}
