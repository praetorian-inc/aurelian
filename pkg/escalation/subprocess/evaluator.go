package subprocess

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// Evaluator implements the subprocess Handler interface using Aurelian's
// PolicyEvaluator. It loads GAAD data and answers permission queries.
type Evaluator struct {
	gaad        *types.AuthorizationAccountDetails
	orgPolicies *orgpolicies.OrgPolicies
	policyData  *iam.PolicyData
	evaluator   *iam.PolicyEvaluator
}

// NewEvaluator creates a new subprocess evaluator from loaded IAM data.
func NewEvaluator(gaad *types.AuthorizationAccountDetails, orgPolicies *orgpolicies.OrgPolicies, resourcePolicies map[string]*types.Policy) *Evaluator {
	pd := iam.NewPolicyData(gaad, orgPolicies, resourcePolicies, nil)
	return &Evaluator{
		gaad:        gaad,
		orgPolicies: orgPolicies,
		policyData:  pd,
		evaluator:   iam.NewPolicyEvaluator(pd),
	}
}

// CheckSpecific evaluates whether principal can perform action on target.
func (e *Evaluator) CheckSpecific(principal, action, target string) (*CheckResponse, error) {
	identityStmts, boundaryStmts := e.collectStatementsForPrincipal(principal)
	return e.checkWithStatements(principal, action, target, identityStmts, boundaryStmts)
}

// checkWithStatements runs the target-dependent half of an evaluation against
// pre-collected principal statements. CheckSpecific collects per call;
// WhoCanBulk collects once per principal and reuses the result across every
// target. The statements are read-only input to Evaluate, so sharing one copy
// across targets is safe and yields identical results to a per-call collection.
func (e *Evaluator) checkWithStatements(principal, action, target string, identityStmts, boundaryStmts *types.PolicyStatementList) (*CheckResponse, error) {
	rc := e.buildRequestContext(principal, target)
	if err := rc.PopulateDefaultRequestConditionKeys(target); err != nil {
		return nil, fmt.Errorf("populating request context: %w", err)
	}

	result, err := e.evaluator.Evaluate(&iam.EvaluationRequest{
		Action:             action,
		Resource:           target,
		Context:            rc,
		IdentityStatements: identityStmts,
		BoundaryStatements: boundaryStmts,
	})
	if err != nil {
		return nil, err
	}

	if !result.Allowed {
		return &CheckResponse{Result: "denied", ResourceConstraint: nil}, nil
	}

	conditions := extractConditionsFromResult(result)
	return &CheckResponse{
		Result:             "allowed",
		Conditions:         conditions,
		ResourceConstraint: nil,
	}, nil
}

// bulkJob is one (principal, target) cell of a who_can_bulk cross-product. The
// statement slices are collected once per principal and shared read-only across
// that principal's targets; Evaluate never mutates them, so this is concurrency
// safe (see checkWithStatements).
type bulkJob struct {
	principal     string
	target        string
	identityStmts *types.PolicyStatementList
	boundaryStmts *types.PolicyStatementList
}

// WhoCanBulk evaluates the principals × targets cross-product for a single
// action, returning only allowed grants in principals-outer, targets-inner
// order. Per-principal statement collection is hoisted out of the target loop,
// and the per-cell evaluations (the dominant cost) are spread across a worker
// pool sized by AURELIAN_EVAL_WORKERS, defaulting to GOMAXPROCS. Output order is
// independent of completion order, so results are deterministic and identical to
// a serial run regardless of worker count.
func (e *Evaluator) WhoCanBulk(action string, principals, targets []string) ([]Grant, error) {
	workers := bulkWorkerCount()
	cells := len(principals) * len(targets)
	started := time.Now()
	defer func() {
		// Per-call progress to stderr (stdout carries the protocol stream).
		// Pairs with the engine's "prewarm call i" line for a both-sides view.
		slog.Info("who_can_bulk done",
			"action", action,
			"principals", len(principals),
			"targets", len(targets),
			"cells", cells,
			"workers", workers,
			"elapsed", time.Since(started).String(),
		)
	}()

	if workers <= 1 || len(principals) == 0 || len(targets) == 0 {
		return e.whoCanBulkSerial(action, principals, targets)
	}

	// Collect per-principal statements once (here, on the dispatching goroutine —
	// workers never collect, so the GAAD is only read concurrently) and flatten
	// the cross-product into indexed jobs.
	jobs := make([]bulkJob, 0, len(principals)*len(targets))
	for _, principal := range principals {
		identityStmts, boundaryStmts := e.collectStatementsForPrincipal(principal)
		for _, target := range targets {
			jobs = append(jobs, bulkJob{principal, target, identityStmts, boundaryStmts})
		}
	}

	// results[i] holds the grant for jobs[i] (nil = denied/skipped). Each index
	// is written by exactly one worker, so no synchronization is needed on it.
	results := make([]*Grant, len(jobs))
	var (
		firstErr error
		errOnce  sync.Once
	)
	done := make(chan struct{})
	idx := make(chan int)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				j := jobs[i]
				resp, err := e.checkWithStatements(j.principal, action, j.target, j.identityStmts, j.boundaryStmts)
				if err != nil {
					errOnce.Do(func() {
						firstErr = fmt.Errorf("evaluating %s -> %s on %s: %w", j.principal, action, j.target, err)
						close(done)
					})
					return
				}
				if resp.Result != "allowed" {
					continue
				}
				conditions := resp.Conditions
				if conditions == nil {
					conditions = []Condition{}
				}
				results[i] = &Grant{
					Principal:  j.principal,
					Target:     j.target,
					Result:     "allowed",
					Conditions: conditions,
				}
			}
		}()
	}

	// Feed job indices, stopping early if a worker reports an error.
	go func() {
		defer close(idx)
		for i := range jobs {
			select {
			case idx <- i:
			case <-done:
				return
			}
		}
	}()

	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	// Compact in index order → identical ordering to the serial path.
	grants := make([]Grant, 0, len(jobs))
	for _, g := range results {
		if g != nil {
			grants = append(grants, *g)
		}
	}
	return grants, nil
}

// WhoCan evaluates action for the given principals against every identity
// ARN in the GAAD (Users, Roles, and Groups — the same set ListGrants
// walks). Each (principal, target) pair is evaluated independently via
// WhoCanBulk so a deny on one target cannot be reused as the verdict for
// another.
func (e *Evaluator) WhoCan(action string, principals []string) ([]Grant, error) {
	universe := make([]string, 0)
	e.gaad.Users.Range(func(_ string, u types.UserDetail) bool {
		universe = append(universe, u.Arn)
		return true
	})
	e.gaad.Roles.Range(func(_ string, r types.RoleDetail) bool {
		universe = append(universe, r.Arn)
		return true
	})
	e.gaad.Groups.Range(func(_ string, g types.GroupDetail) bool {
		universe = append(universe, g.Arn)
		return true
	})
	return e.WhoCanBulk(action, principals, universe)
}

// whoCanBulkSerial is the single-threaded cross-product. It is the worker=1
// fallback and the reference behavior the parallel path must match exactly.
func (e *Evaluator) whoCanBulkSerial(action string, principals, targets []string) ([]Grant, error) {
	grants := make([]Grant, 0)
	for _, principal := range principals {
		identityStmts, boundaryStmts := e.collectStatementsForPrincipal(principal)
		for _, target := range targets {
			resp, err := e.checkWithStatements(principal, action, target, identityStmts, boundaryStmts)
			if err != nil {
				return nil, fmt.Errorf("evaluating %s -> %s on %s: %w", principal, action, target, err)
			}
			if resp.Result != "allowed" {
				continue
			}
			conditions := resp.Conditions
			if conditions == nil {
				conditions = []Condition{}
			}
			grants = append(grants, Grant{
				Principal:  principal,
				Target:     target,
				Result:     "allowed",
				Conditions: conditions,
			})
		}
	}
	return grants, nil
}

// bulkWorkerCount returns the configured worker pool size for WhoCanBulk:
// AURELIAN_EVAL_WORKERS if set to a positive integer, else GOMAXPROCS.
func bulkWorkerCount() int {
	if v := os.Getenv("AURELIAN_EVAL_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return runtime.GOMAXPROCS(0)
}

// CheckAnyTarget evaluates whether principal can perform action on any resource.
// Unlike CheckSpecific, this scans identity policy statements directly rather
// than using the full evaluator (which requires a concrete resource ARN for
// action/resource validation).
func (e *Evaluator) CheckAnyTarget(principal, action string) (*CheckResponse, error) {
	identityStmts, _ := e.collectStatementsForPrincipal(principal)
	if identityStmts == nil || len(*identityStmts) == 0 {
		return &CheckResponse{Result: "denied", ResourceConstraint: nil}, nil
	}

	// Scan for any Allow statement matching the action.
	var constraint *string
	found := false
	for _, stmt := range *identityStmts {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		if stmt.Action == nil {
			continue
		}
		actionMatches := false
		for _, a := range *stmt.Action {
			if iam.MatchesPattern(a, action) {
				actionMatches = true
				break
			}
		}
		if !actionMatches {
			continue
		}
		found = true
		// Extract the most specific resource constraint.
		if stmt.Resource != nil {
			for _, r := range *stmt.Resource {
				if r != "*" {
					constraint = &r
				}
			}
		}
	}

	if !found {
		return &CheckResponse{Result: "denied", ResourceConstraint: nil}, nil
	}

	return &CheckResponse{
		Result:             "allowed",
		Conditions:         nil,
		ResourceConstraint: constraint,
	}, nil
}

// CheckCounterfactual evaluates the permission with specified deny statements removed.
// Removed statements are filtered from both identity policies and permission boundaries.
func (e *Evaluator) CheckCounterfactual(principal, action, target string, removed []RemovedStatement) (*CheckResponse, error) {
	identityStmts, boundaryStmts := e.collectStatementsForPrincipal(principal)

	// Filter out removed deny statements from both identity and boundary.
	filteredIdentity := filterRemovedStatements(identityStmts, removed)
	filteredBoundary := filterRemovedStatements(boundaryStmts, removed)

	rc := e.buildRequestContext(principal, target)
	if err := rc.PopulateDefaultRequestConditionKeys(target); err != nil {
		return nil, fmt.Errorf("populating request context: %w", err)
	}

	result, err := e.evaluator.Evaluate(&iam.EvaluationRequest{
		Action:             action,
		Resource:           target,
		Context:            rc,
		IdentityStatements: filteredIdentity,
		BoundaryStatements: filteredBoundary,
	})
	if err != nil {
		return nil, err
	}

	if !result.Allowed {
		return &CheckResponse{Result: "denied", ResourceConstraint: nil}, nil
	}

	conditions := extractConditionsFromResult(result)
	return &CheckResponse{
		Result:             "allowed",
		Conditions:         conditions,
		ResourceConstraint: nil,
	}, nil
}

// collectStatementsForPrincipal gathers identity and boundary statements for a
// principal ARN by looking it up in the GAAD.
func (e *Evaluator) collectStatementsForPrincipal(principalArn string) (*types.PolicyStatementList, *types.PolicyStatementList) {
	// The GAAD maps are keyed by ARN (see types.NewAuthorizationAccountDetails),
	// so look the principal up directly rather than scanning every entry. This
	// runs once per (principal, target) pair in who_can_bulk, so an O(1) Get
	// instead of an O(users+roles) Range is a large win at account scale.

	// Try as a user.
	if user, ok := e.gaad.Users.Get(principalArn); ok {
		identity := e.collectUserStatements(&user)
		boundary := e.resolveBoundary(user.PermissionsBoundary)
		return &identity, boundary
	}

	// Try as a role.
	if role, ok := e.gaad.Roles.Get(principalArn); ok {
		identity := e.collectRoleStatements(&role)
		boundary := e.resolveBoundary(role.PermissionsBoundary)
		return &identity, boundary
	}

	// Unknown principal — return empty statements.
	empty := types.PolicyStatementList{}
	return &empty, nil
}

func (e *Evaluator) collectUserStatements(user *types.UserDetail) types.PolicyStatementList {
	var stmts types.PolicyStatementList
	for _, p := range user.UserPolicyList {
		if p.PolicyDocument.Statement != nil {
			stmts = append(stmts, *p.PolicyDocument.Statement...)
		}
	}
	for _, mp := range user.AttachedManagedPolicies {
		stmts = append(stmts, e.resolveManagedPolicy(mp)...)
	}
	for _, groupName := range user.GroupList {
		e.gaad.Groups.Range(func(_ string, g types.GroupDetail) bool {
			if g.GroupName != groupName {
				return true
			}
			for _, p := range g.GroupPolicyList {
				if p.PolicyDocument.Statement != nil {
					stmts = append(stmts, *p.PolicyDocument.Statement...)
				}
			}
			for _, mp := range g.AttachedManagedPolicies {
				stmts = append(stmts, e.resolveManagedPolicy(mp)...)
			}
			return false
		})
	}
	return stmts
}

func (e *Evaluator) collectRoleStatements(role *types.RoleDetail) types.PolicyStatementList {
	var stmts types.PolicyStatementList
	for _, p := range role.RolePolicyList {
		if p.PolicyDocument.Statement != nil {
			stmts = append(stmts, *p.PolicyDocument.Statement...)
		}
	}
	for _, mp := range role.AttachedManagedPolicies {
		stmts = append(stmts, e.resolveManagedPolicy(mp)...)
	}
	return stmts
}

func (e *Evaluator) resolveManagedPolicy(mp types.ManagedPolicy) types.PolicyStatementList {
	policy, ok := e.gaad.Policies.Get(mp.PolicyArn)
	if !ok {
		return nil
	}
	doc := policy.DefaultPolicyDocument()
	if doc == nil || doc.Statement == nil {
		return nil
	}
	return *doc.Statement
}

func (e *Evaluator) resolveBoundary(boundary types.ManagedPolicy) *types.PolicyStatementList {
	if boundary.PolicyArn == "" {
		return nil
	}
	stmts := e.resolveManagedPolicy(boundary)
	if stmts == nil {
		return nil
	}
	return &stmts
}

func (e *Evaluator) buildRequestContext(principalArn, resourceArn string) *iam.RequestContext {
	principalAccount := ""
	resourceAccount := ""
	if parsed, err := arn.Parse(principalArn); err == nil {
		principalAccount = parsed.AccountID
	}
	if parsed, err := arn.Parse(resourceArn); err == nil {
		resourceAccount = parsed.AccountID
	}
	if resourceAccount == "" {
		resourceAccount = principalAccount
	}

	return &iam.RequestContext{
		PrincipalArn:     principalArn,
		PrincipalAccount: principalAccount,
		ResourceAccount:  resourceAccount,
		CurrentTime:      time.Now(),
		SecureTransport:  iam.Bool(true),
	}
}

// extractConditionsFromResult extracts IAM conditions from the evaluation result.
func extractConditionsFromResult(result *iam.EvaluationResult) []Condition {
	if result == nil || result.PolicyResult == nil {
		return nil
	}
	var conditions []Condition
	for _, evals := range result.PolicyResult.Evaluations {
		for _, eval := range evals {
			if eval.ConditionEvaluation != nil && eval.ConditionEvaluation.Conditions != nil {
				for _, c := range eval.ConditionEvaluation.Conditions {
					if c == nil {
						continue
					}
					for operator, condStmt := range *c {
						for key, values := range condStmt {
							conditions = append(conditions, Condition{
								Key:      key,
								Operator: operator,
								Values:   []string(values),
							})
						}
					}
				}
			}
		}
	}
	return conditions
}

// filterRemovedStatements returns a copy of stmts with any matching deny
// statements from removed excluded.
func filterRemovedStatements(stmts *types.PolicyStatementList, removed []RemovedStatement) *types.PolicyStatementList {
	if stmts == nil || len(removed) == 0 {
		return stmts
	}
	filtered := make(types.PolicyStatementList, 0, len(*stmts))
	for _, stmt := range *stmts {
		if shouldRemove(stmt, removed) {
			continue
		}
		filtered = append(filtered, stmt)
	}
	return &filtered
}

func shouldRemove(stmt types.PolicyStatement, removed []RemovedStatement) bool {
	if !strings.EqualFold(stmt.Effect, "Deny") {
		return false
	}
	for _, r := range removed {
		if !strings.EqualFold(r.Effect, "Deny") {
			continue
		}
		if stmt.Action != nil {
			for _, a := range *stmt.Action {
				if iam.MatchesPattern(a, r.Action) || iam.MatchesPattern(r.Action, a) {
					if stmt.Resource != nil {
						for _, res := range *stmt.Resource {
							if iam.MatchesPattern(res, r.Resource) || iam.MatchesPattern(r.Resource, res) {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

// ListGrants returns the effective policy statements for every principal.
// The solver uses this to build a PermissionIndex for target/actor pruning.
// Response shape mirrors policy_summary entries.
func (e *Evaluator) ListGrants() (*ListGrantsResponse, error) {
	var entries []ListGrantsEntry

	e.gaad.Users.Range(func(_ string, u types.UserDetail) bool {
		stmts := e.collectUserStatements(&u)
		entries = append(entries, ListGrantsEntry{
			Principal:           u.Arn,
			EffectiveStatements: flattenToGrantStatements(stmts),
		})
		return true
	})

	e.gaad.Roles.Range(func(_ string, r types.RoleDetail) bool {
		stmts := e.collectRoleStatements(&r)
		entries = append(entries, ListGrantsEntry{
			Principal:           r.Arn,
			EffectiveStatements: flattenToGrantStatements(stmts),
		})
		return true
	})

	e.gaad.Groups.Range(func(_ string, g types.GroupDetail) bool {
		var stmts types.PolicyStatementList
		for _, p := range g.GroupPolicyList {
			if p.PolicyDocument.Statement != nil {
				stmts = append(stmts, *p.PolicyDocument.Statement...)
			}
		}
		for _, mp := range g.AttachedManagedPolicies {
			stmts = append(stmts, e.resolveManagedPolicy(mp)...)
		}
		entries = append(entries, ListGrantsEntry{
			Principal:           g.Arn,
			EffectiveStatements: flattenToGrantStatements(stmts),
		})
		return true
	})

	return &ListGrantsResponse{Entries: entries}, nil
}

// flattenToGrantStatements converts policy statements into the list_grants
// response format. Each (action, resource) pair becomes a separate entry.
// Conditions are omitted — the index only needs effect/action/resource.
func flattenToGrantStatements(stmts types.PolicyStatementList) []ListGrantsStatement {
	var result []ListGrantsStatement
	for _, stmt := range stmts {
		actions := stmtActions(&stmt)
		resources := stmtResources(&stmt)
		effect := "Allow"
		if strings.EqualFold(stmt.Effect, "Deny") {
			effect = "Deny"
		}
		for _, action := range actions {
			for _, resource := range resources {
				result = append(result, ListGrantsStatement{
					Effect:   effect,
					Action:   action,
					Resource: resource,
				})
			}
		}
	}
	if result == nil {
		result = []ListGrantsStatement{}
	}
	return result
}

func stmtActions(stmt *types.PolicyStatement) []string {
	if stmt.Action != nil {
		return []string(*stmt.Action)
	}
	return []string{"*"}
}

func stmtResources(stmt *types.PolicyStatement) []string {
	if stmt.Resource != nil {
		return []string(*stmt.Resource)
	}
	return []string{"*"}
}

// NewEvaluatorFromData creates an evaluator from GAAD data and collected resources.
// This is a convenience for the CLI module.
func NewEvaluatorFromData(gaad *types.AuthorizationAccountDetails, orgPolicies *orgpolicies.OrgPolicies, resources store.Map[output.AWSResource]) *Evaluator {
	resourcePolicies := make(map[string]*types.Policy)
	resources.Range(func(_ string, r output.AWSResource) bool {
		if r.ResourcePolicy != nil {
			resourcePolicies[r.ARN] = r.ResourcePolicy
		}
		return true
	})
	return NewEvaluator(gaad, orgPolicies, resourcePolicies)
}
