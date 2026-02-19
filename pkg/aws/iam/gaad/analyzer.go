// Package gaad implements the GaadAnalyzer, which evaluates IAM principal
// permissions against cloud resources and organization policies to detect
// privilege escalation paths.
package gaad

import (
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
	ctx := newAnalyzerContext(gaad, orgPolicies, resources)

	summary := iam.NewPermissionsSummary()
	evalChan := make(chan *iam.EvaluationRequest, 1000)

	// Start evaluation workers
	var evalWg sync.WaitGroup
	ctx.startEvaluationWorkers(evalChan, summary, &evalWg)

	// Start producers
	var producerWg sync.WaitGroup

	for i := range gaad.UserDetailList {
		user := gaad.UserDetailList[i]
		producerWg.Add(1)
		go func() {
			defer producerWg.Done()
			ctx.processUserPermissions(user, evalChan)
		}()
	}

	// TODO (4c): processRolePermissions
	// TODO (4d): generateServicePrincipalEvaluations
	// TODO (4e): processAssumeRolePolicies

	producerWg.Wait()
	close(evalChan)
	evalWg.Wait()

	// TODO (4f): applyCreateThenUseEdges

	return ctx.buildRelationships(summary), nil
}
