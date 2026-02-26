package gaad

import "github.com/praetorian-inc/aurelian/pkg/types"

// copyStatementsWithOrigin returns copies of statements with OriginArn set on
// each copy. The original GAAD statements are never mutated, eliminating the
// data-race that occurred when multiple goroutines decorated the same shared
// policy statements concurrently.
func copyStatementsWithOrigin(stmts *types.PolicyStatementList, originArn string) types.PolicyStatementList {
	if stmts == nil || len(*stmts) == 0 {
		return nil
	}
	out := make(types.PolicyStatementList, len(*stmts))
	copy(out, *stmts) // shallow copy each struct — pointer fields (Action, Resource, etc.) are read-only
	for i := range out {
		out[i].OriginArn = originArn
	}
	return out
}

// collectInlineStatements extracts and copies statements from inline policies,
// decorating each with originArn. Works for UserPolicyList, RolePolicyList,
// and GroupPolicyList (all []types.InlinePolicy).
func collectInlineStatements(policies []types.InlinePolicy, originArn string) types.PolicyStatementList {
	var stmts types.PolicyStatementList
	for _, p := range policies {
		if p.PolicyDocument.Statement != nil {
			stmts = append(stmts, copyStatementsWithOrigin(p.PolicyDocument.Statement, originArn)...)
		}
	}
	return stmts
}

// collectManagedPolicyStatements extracts and copies statements from attached
// managed policies. Each statement's OriginArn is set to the managed policy's
// ARN. Works for user, role, and group attached managed policies.
func collectManagedPolicyStatements(state *AnalyzerState, policies []types.ManagedPolicy) types.PolicyStatementList {
	var stmts types.PolicyStatementList
	for _, attached := range policies {
		policy := state.GetPolicyByArn(attached.PolicyArn)
		if policy == nil {
			continue
		}
		doc := policy.DefaultPolicyDocument()
		if doc == nil || doc.Statement == nil {
			continue
		}
		stmts = append(stmts, copyStatementsWithOrigin(doc.Statement, attached.PolicyArn)...)
	}
	return stmts
}

// collectBoundaryStatements extracts and copies permission boundary statements.
func collectBoundaryStatements(state *AnalyzerState, boundary types.PermissionsBoundary) types.PolicyStatementList {
	if boundary == (types.PermissionsBoundary{}) {
		return nil
	}
	policy := state.GetPolicyByArn(boundary.PermissionsBoundaryArn)
	if policy == nil {
		return nil
	}
	doc := policy.DefaultPolicyDocument()
	if doc == nil || doc.Statement == nil {
		return nil
	}
	return copyStatementsWithOrigin(doc.Statement, boundary.PermissionsBoundaryArn)
}
