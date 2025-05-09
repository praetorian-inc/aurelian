package aws

import (
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/nebula/pkg/types"
)

// GaadAnalyzer handles efficient analysis of GAAD policy data
type GaadAnalyzer struct {
	policyData *PolicyData
	evaluator  *PolicyEvaluator
}

// NewGaadAnalyzer creates a new analyzer and initializes caches
func NewGaadAnalyzer(pd *PolicyData) *GaadAnalyzer {
	evaluator := NewPolicyEvaluator(pd)
	ga := &GaadAnalyzer{
		policyData: pd,
		evaluator:  evaluator,
	}
	initializeCaches(pd)
	addServicesToResourceCache()
	return ga
}

// AnalyzePrincipalPermissions processes permissions for IAM principals concurrently
func (ga *GaadAnalyzer) AnalyzePrincipalPermissions() (*PermissionsSummary, error) {
	summary := NewPermissionsSummary()
	var wg sync.WaitGroup

	// Create buffered channel for evaluation requests
	evalChan := make(chan *EvaluationRequest, 1000)

	// Start evaluation workers
	var evalWg sync.WaitGroup
	ga.startEvaluationWorkers(evalChan, summary, &evalWg)

	// Process users
	for _, user := range ga.policyData.Gaad.UserDetailList {
		wg.Add(1)
		go func(u types.UserDL) {
			defer wg.Done()
			ga.processUserPermissions(u, evalChan)
		}(user)
	}

	for _, role := range ga.policyData.Gaad.RoleDetailList {
		wg.Add(1)
		go func(r types.RoleDL) {
			defer wg.Done()
			ga.processRolePermissions(r, evalChan)
		}(role)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ga.generateServicePrincipalEvaluations(evalChan)
	}()

	// Process direct assume role policies for direct principal access
	wg.Add(1)
	go func() {
		defer wg.Done()
		ga.processAssumeRolePolicies(evalChan)
	}()

	// Wait for all producers to finish
	wg.Wait()

	// Close the channel to signal workers to exit
	close(evalChan)

	// Wait for all workers to finish
	evalWg.Wait()

	return summary, nil
}

func (ga *GaadAnalyzer) generateServicePrincipalEvaluations(evalChan chan *EvaluationRequest) {

	// Process resource policies
	for resourceArn := range ga.policyData.ResourcePolicies {
		policy := ga.policyData.ResourcePolicies[resourceArn]
		evalReq := ga.generateServiceEvaluations(resourceArn, policy)
		if evalReq != nil {
			evalChan <- evalReq
		}
	}

	// Proccess AssumeRole policies
	// for _, role := range ga.policyData.Gaad.RoleDetailList {
	// 	for i, stmt := range *role.AssumeRolePolicyDocument.Statement {
	// 		(*role.AssumeRolePolicyDocument.Statement)[i].OriginArn = role.Arn
	// 		(*role.AssumeRolePolicyDocument.Statement)[i].Resource = &types.DynaString{role.Arn}
	// 		if stmt.Principal != nil && stmt.Principal.Service != nil {
	// 			for _, service := range *stmt.Principal.Service {
	// 				for _, action := range *stmt.Action {
	// 					if isPrivEscAction(action) {

	// 						accountID, tags := getResourceDeets(role.Arn)
	// 						rc := &RequestContext{
	// 							PrincipalArn:     service,
	// 							ResourceTags:     tags,
	// 							PrincipalAccount: accountID,
	// 							CurrentTime:      time.Now(),
	// 						}
	// 						rc.PopulateDefaultRequestConditionKeys(role.Arn)

	// 						evalReq := &EvaluationRequest{
	// 							Action:             action,
	// 							Resource:           role.Arn,
	// 							IdentityStatements: role.AssumeRolePolicyDocument.Statement,
	// 							Context:            rc,
	// 						}
	// 						evalChan <- evalReq
	// 					}
	// 				}
	// 			}
	// 		}
	// 	}
	// }
}

func (ga *GaadAnalyzer) generateServiceEvaluations(resourceArn string, policy *types.Policy) *EvaluationRequest {
	if policy.Statement != nil {
		for i := range *policy.Statement {
			(*policy.Statement)[i].OriginArn = resourceArn
			if (*policy.Statement)[i].Principal != nil && (*policy.Statement)[i].Principal.Service != nil {
				for _, service := range *(*policy.Statement)[i].Principal.Service {
					for _, action := range *(*policy.Statement)[i].Action {
						if isPrivEscAction(action) {

							accountID, tags := getResourceDeets(resourceArn)

							rc := &RequestContext{
								PrincipalArn:     service,
								ResourceTags:     tags,
								PrincipalAccount: accountID,
								CurrentTime:      time.Now(),
							}
							rc.PopulateDefaultRequestConditionKeys(resourceArn)

							evalReq := &EvaluationRequest{
								Action:             action,
								Resource:           resourceArn,
								IdentityStatements: policy.Statement,
								Context:            rc,
							}
							return evalReq
						}
					}
				}
			}
		}
	}
	return nil
}

// Modified process methods to gather all policies
func (ga *GaadAnalyzer) processUserPermissions(user types.UserDL, evalChan chan<- *EvaluationRequest) {
	// Create identity statements list
	identityStatements := types.PolicyStatementList{}
	boundaryStatements := types.PolicyStatementList{}

	// Add inline policies
	for _, policy := range user.UserPolicyList {
		if policy.PolicyDocument.Statement != nil {
			// Decorate with user's ARN
			for i := range *policy.PolicyDocument.Statement {
				(*policy.PolicyDocument.Statement)[i].OriginArn = user.Arn
			}
			identityStatements = append(identityStatements, *policy.PolicyDocument.Statement...)
		}
	}

	// Add managed policies
	identityStatements = append(identityStatements, getUserAttachedManagedPolicies(user)...)

	// Add permissions boundary
	if user.PermissionsBoundary != (types.ManagedPL{}) {
		if boundaryPolicy := getPolicyByArn(user.PermissionsBoundary.PolicyArn); boundaryPolicy != nil {
			if boundaryDoc := boundaryPolicy.DefaultPolicyDocument(); boundaryDoc != nil {
				for i := range *boundaryDoc.Statement {
					(*boundaryDoc.Statement)[i].OriginArn = user.PermissionsBoundary.PolicyArn
				}
				boundaryStatements = *boundaryDoc.Statement
			}
		}
	}

	// Process group policies
	for _, groupName := range user.GroupList {
		if group, exists := ga.getGroupByName(groupName); exists {
			// Add group inline policies
			for _, policy := range group.GroupPolicyList {
				if policy.PolicyDocument.Statement != nil {
					for i := range *policy.PolicyDocument.Statement {
						(*policy.PolicyDocument.Statement)[i].OriginArn = group.Arn
					}
					identityStatements = append(identityStatements, *policy.PolicyDocument.Statement...)
				}
			}
			// Add group managed policies
			for _, attachedPolicy := range group.AttachedManagedPolicies {
				if policy := getPolicyByArn(attachedPolicy.PolicyArn); policy != nil {
					if doc := policy.DefaultPolicyDocument(); doc != nil && doc.Statement != nil {
						for i := range *doc.Statement {
							(*doc.Statement)[i].OriginArn = attachedPolicy.PolicyArn
						}
						identityStatements = append(identityStatements, *doc.Statement...)
					}
				}
			}
		}
	}

	// Extract and process actions/resources
	allActions := ExtractActions(&identityStatements)

	// Generate evaluation requests
	for _, action := range allActions {
		if isPrivEscAction(action) {

			// tempBoundary := make(types.PolicyStatementList, 0)
			// deepCopy(boundaryStatements, &tempBoundary)
			for _, resource := range getResourcesByAction(Action(action)) {

				// For AssumeRole actions, update the resource in the policy document
				// Without the resource, the evaluator won't match the policy
				if action == "sts:AssumeRole" {
					role := roleCache[resource.Arn.String()]
					if role != nil {
						arpd := role.AssumeRolePolicyDocument
						for i := range *arpd.Statement {
							(*arpd.Statement)[i].Resource = &types.DynaString{resource.Arn.String()}
						}

						slog.Debug(fmt.Sprintf("AssumeRole policy for %s: %v", role.Arn, arpd.Statement))
						// tempBoundary = append(tempBoundary, *arpd.Statement...)
					}
				}

				rc := &RequestContext{
					PrincipalArn:     user.Arn,
					ResourceTags:     resource.Tags(),
					PrincipalAccount: resource.AccountId,
					CurrentTime:      time.Now(),
				}
				rc.PopulateDefaultRequestConditionKeys(resource.Arn.String())

				evalReq := &EvaluationRequest{
					Action:             action,
					Resource:           getIdentifierForEvalRequest(resource),
					IdentityStatements: &identityStatements,
					BoundaryStatements: &boundaryStatements,
					Context:            rc,
				}
				evalChan <- evalReq
			}
		}
	}
}

func (ga *GaadAnalyzer) startEvaluationWorkers(evalChan <-chan *EvaluationRequest, summary *PermissionsSummary, wg *sync.WaitGroup) {
	numWorkers := runtime.NumCPU() * 3
	slog.Debug(fmt.Sprintf("Starting %d evaluation workers", numWorkers))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for req := range evalChan {
				// This loop will exit when evalChan is closed
				result, err := ga.evaluator.Evaluate(req)
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

				summary.AddPermission(req.Context.PrincipalArn, req.Resource,
					req.Action, result.Allowed, result)
			}
		}()
	}
}

func (ga *GaadAnalyzer) processRolePermissions(role types.RoleDL, evalChan chan<- *EvaluationRequest) {
	identityStatements := types.PolicyStatementList{}
	boundaryStatements := types.PolicyStatementList{}

	// Add inline policies
	for _, policy := range role.RolePolicyList {
		// Decorate the policy with the role's ARN
		for stmt := range *policy.PolicyDocument.Statement {
			(*policy.PolicyDocument.Statement)[stmt].OriginArn = role.Arn
		}
		slog.Debug(fmt.Sprintf("Role policy for %s: %v", role.Arn, policy.PolicyDocument.Statement))
		identityStatements = append(identityStatements, *policy.PolicyDocument.Statement...)
	}

	// Add managed policies
	identityStatements = append(identityStatements, getRoleAttachedManagedPolicies(role)...)

	//Set permissions boundary if present
	if role.PermissionsBoundary != (types.ManagedPL{}) {
		if boundaryPolicy := getPolicyByArn(role.PermissionsBoundary.PolicyArn); boundaryPolicy != nil {
			if boundaryDoc := boundaryPolicy.DefaultPolicyDocument(); boundaryDoc != nil {
				for i := range *boundaryDoc.Statement {
					(*boundaryDoc.Statement)[i].OriginArn = role.PermissionsBoundary.PolicyArn
				}
				boundaryStatements = *boundaryDoc.Statement
			}
		}
	}

	// Extract and process actions/resources
	allActions := ExtractActions(&identityStatements)

	// Generate evaluation requests
	for _, action := range allActions {
		if isPrivEscAction(action) {

			tempBoundary := make(types.PolicyStatementList, 0)
			deepCopy(boundaryStatements, &tempBoundary)

			for _, resource := range getResourcesByAction(Action(action)) {
				// For AssumeRole actions, update the resource in the policy document
				// Without the resource, the evaluator won't match the policy
				if action == "sts:AssumeRole" {
					role := roleCache[resource.Arn.String()]
					if role != nil {
						arpd := role.AssumeRolePolicyDocument
						for i := range *arpd.Statement {
							(*arpd.Statement)[i].Resource = &types.DynaString{resource.Arn.String()}
						}

						slog.Debug(fmt.Sprintf("AssumeRole policy for %s: %v", role.Arn, arpd.Statement))
						tempBoundary = append(tempBoundary, *arpd.Statement...)
					}
				}
				rc := &RequestContext{
					PrincipalArn:     role.Arn,
					ResourceTags:     resource.Tags(),
					PrincipalAccount: resource.AccountId,
					CurrentTime:      time.Now(),
				}
				rc.PopulateDefaultRequestConditionKeys(resource.Arn.String())

				evalReq := &EvaluationRequest{
					Action:             action,
					Resource:           getIdentifierForEvalRequest(resource),
					IdentityStatements: &identityStatements,
					BoundaryStatements: &boundaryStatements,
					Context:            rc,
				}
				evalChan <- evalReq
			}
		}
	}
}

func (ga *GaadAnalyzer) processAssumeRolePolicies(evalChan chan<- *EvaluationRequest) {
	// Process all roles' assume role policy documents
	for _, role := range ga.policyData.Gaad.RoleDetailList {
		// Skip if there's no policy document or statements
		if role.AssumeRolePolicyDocument.Statement == nil || len(*role.AssumeRolePolicyDocument.Statement) == 0 {
			continue
		}

		// Extract the principals that can assume this role
		for _, stmt := range *role.AssumeRolePolicyDocument.Statement {
			// Skip if not an allow statement
			if strings.ToLower(stmt.Effect) != "allow" {
				continue
			}

			// Process principals from different types
			principals := stmt.ExtractPrincipals()
			for _, principal := range principals {
				// Create the evaluation context
				accountID, tags := getResourceDeets(role.Arn)

				rc := &RequestContext{
					PrincipalArn:     principal,
					ResourceTags:     tags,
					PrincipalAccount: accountID,
					CurrentTime:      time.Now(),
					SecureTransport:  Bool(true),
				}
				rc.PopulateDefaultRequestConditionKeys(role.Arn)

				// Create the evaluation request
				evalReq := &EvaluationRequest{
					Action:             "sts:AssumeRole",
					Resource:           role.Arn,
					IdentityStatements: &types.PolicyStatementList{},
					Context:            rc,
				}

				// Send the evaluation request
				evalChan <- evalReq
			}
		}
	}
}

// getGroupByName retrieves a group by name
func (ga *GaadAnalyzer) getGroupByName(name string) (*types.GroupDL, bool) {
	for _, group := range ga.policyData.Gaad.GroupDetailList {
		if group.GroupName == name {
			return &group, true
		}
	}
	return nil, false
}
