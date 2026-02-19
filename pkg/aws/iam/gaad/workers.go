package gaad

import (
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// startEvaluationWorkers launches a pool of goroutines that consume
// EvaluationRequests and accumulate results into the PermissionsSummary.
func (ctx *analyzerContext) startEvaluationWorkers(
	evalChan <-chan *iam.EvaluationRequest,
	summary *iam.PermissionsSummary,
	wg *sync.WaitGroup,
) {
	numWorkers := runtime.NumCPU() * 3
	slog.Debug(fmt.Sprintf("Starting %d evaluation workers", numWorkers))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range evalChan {
				result, err := ctx.evaluator.Evaluate(req)
				if err != nil {
					slog.Error("Error evaluating permissions",
						"principal", req.Context.PrincipalArn,
						"resource", req.Resource,
						"action", req.Action,
						"error", err)
					continue
				}

				slog.Debug(fmt.Sprintf("EvaluationRequest: %s, EvaluationResult: %s",
					req.String(), result.String()))

				summary.AddPermission(
					req.Context.PrincipalArn, req.Resource,
					req.Action, result.Allowed, result,
				)
			}
		}()
	}
}

// buildRelationships converts a PermissionsSummary into the output type.
func (ctx *analyzerContext) buildRelationships(summary *iam.PermissionsSummary) []output.AWSIAMRelationship {
	var results []output.AWSIAMRelationship

	summary.Permissions.Range(func(key, value interface{}) bool {
		perms, ok := value.(*iam.PrincipalPermissions)
		if !ok {
			return true
		}

		principalIAM := ctx.buildPrincipalResource(perms.PrincipalArn)

		perms.ResourcePerms.Range(func(resKey, resValue interface{}) bool {
			resPerm, ok := resValue.(*iam.ResourcePermission)
			if !ok {
				return true
			}

			resArn := resKey.(string)
			resource, ok := ctx.resourceCache[resArn]
			if !ok {
				slog.Error("Resource not found in cache", "resource", resArn)
				return true
			}

			for _, action := range resPerm.AllowedActions {
				results = append(results, output.AWSIAMRelationship{
					Principal: principalIAM,
					Resource:  *resource,
					Action:    action.Name,
				})
			}
			return true
		})

		return true
	})

	return results
}

func (ctx *analyzerContext) buildPrincipalResource(principalArn string) output.AWSIAMResource {
	if user, ok := ctx.userCache[principalArn]; ok {
		return iam.FromUserDL(*user, ctx.gaad.AccountID)
	}
	if role, ok := ctx.roleCache[principalArn]; ok {
		return iam.FromRoleDL(*role)
	}
	if group, ok := ctx.groupCache[principalArn]; ok {
		return iam.FromGroupDL(*group)
	}
	// Service principal or unknown
	return output.AWSIAMResource{
		AWSResource: output.AWSResource{
			Platform:     "aws",
			ResourceType: "AWS::IAM::ServicePrincipal",
			ResourceID:   principalArn,
			ARN:          principalArn,
			DisplayName:  principalArn,
		},
	}
}
