package gaad

import (
	"log/slog"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// processUserPermissions collects all identity and boundary statements for a
// user (including group memberships) and evaluates them against resources.
func (ctx *analyzerContext) processUserPermissions(user types.UserDetail, evalChan chan<- *iam.EvaluationRequest) {
	// Collect all identity statements (copy-safe — no GAAD mutation)
	identityStatements := types.PolicyStatementList{}
	identityStatements = append(identityStatements, collectInlineStatements(user.UserPolicyList, user.Arn)...)
	identityStatements = append(identityStatements, ctx.collectManagedPolicyStatements(user.AttachedManagedPolicies)...)
	identityStatements = append(identityStatements, ctx.collectGroupStatements(user.GroupList)...)

	// Collect boundary statements
	boundaryStatements := ctx.collectBoundaryStatements(user.PermissionsBoundary)

	// Evaluate actions against resources
	ctx.evaluatePrincipalActions(user.Arn, &identityStatements, boundaryStatements, evalChan)
}

// evaluatePrincipalActions expands actions from identity statements, filters to
// privilege-escalation actions, matches resources, and sends EvaluationRequests.
// This is the shared evaluation loop used by both processUserPermissions (4b)
// and processRolePermissions (4c).
func (ctx *analyzerContext) evaluatePrincipalActions(
	principalArn string,
	identityStatements *types.PolicyStatementList,
	boundaryStatements types.PolicyStatementList,
	evalChan chan<- *iam.EvaluationRequest,
) {
	allActions := ctx.extractActions(identityStatements)

	for _, action := range allActions {
		if !iam.IsPrivEscAction(action) {
			continue
		}

		resources := ctx.getResourcesByAction(iam.Action(action))
		if len(resources) == 0 {
			slog.Debug("No resources found for action", "action", action)
			continue
		}

		for _, resource := range resources {
			if resource == nil {
				continue
			}

			resID := resourceIdentifier(resource)
			if resID == "" {
				continue
			}

			rc := &iam.RequestContext{
				PrincipalArn:     principalArn,
				ResourceTags:     extractResourceTags(resource),
				PrincipalAccount: resource.AccountRef,
				CurrentTime:      time.Now(),
			}
			rc.PopulateDefaultRequestConditionKeys(resID)

			var boundaryPtr *types.PolicyStatementList
			if len(boundaryStatements) > 0 {
				boundaryPtr = &boundaryStatements
			}

			evalReq := &iam.EvaluationRequest{
				Action:             action,
				Resource:           resID,
				IdentityStatements: identityStatements,
				BoundaryStatements: boundaryPtr,
				Context:            rc,
			}
			evalChan <- evalReq
		}
	}
}
