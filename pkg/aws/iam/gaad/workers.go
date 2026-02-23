package gaad

import (
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

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
			doEvaluationWork(evalChan, resultChan, evaluator, state)
		}()
	}
}

// doEvaluationWork consumes EvaluationRequests from evalChan, evaluates each,
// and sends allowed results to resultChan. Runs until evalChan is closed.
func doEvaluationWork(
	evalChan <-chan *iam.EvaluationRequest,
	resultChan chan<- output.AWSIAMRelationship,
	evaluator *iam.PolicyEvaluator,
	state AnalyzerState,
) {
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
}

// buildPrincipal looks up a principal ARN in the state and wraps it as an
// AWSIAMResource. If not found, returns a minimal AWSIAMResource. For service
// principals (non-ARN strings like "lambda.amazonaws.com"), a pseudo-ARN is
// synthesized so downstream consumers always receive a valid ARN.
func buildPrincipal(principalArn string, state AnalyzerState) output.AWSIAMResource {
	if r := state.GetResource(principalArn); r != nil {
		return output.FromAWSResource(*r)
	}

	// If it's not a valid ARN, treat it as a service principal and synthesize one.
	if !arn.IsARN(principalArn) {
		serviceArn := types.BuildResourceARN(principalArn, "AWS::Service", "*", "*").String()
		return output.AWSIAMResource{
			AWSResource: output.AWSResource{
				ARN:          serviceArn,
				ResourceID:   principalArn,
				ResourceType: "AWS::Service",
				Region:       "*",
				AccountRef:   "*",
			},
		}
	}

	return output.AWSIAMResource{
		AWSResource: output.AWSResource{
			ARN:        principalArn,
			ResourceID: principalArn,
		},
	}
}
