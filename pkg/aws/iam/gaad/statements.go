package gaad

import "github.com/praetorian-inc/aurelian/pkg/types"

// decorateStatements returns a shallow copy of stmts with OriginArn set on each.
// Pointer fields within each statement (Action, Resource, etc.) are shared with
// the original, but OriginArn is a value field so setting it on the copy is safe.
// The original statements are never mutated.
func decorateStatements(stmts *types.PolicyStatementList, originArn string) types.PolicyStatementList {
	if stmts == nil || len(*stmts) == 0 {
		return nil
	}
	copies := make(types.PolicyStatementList, len(*stmts))
	copy(copies, *stmts)
	for i := range copies {
		copies[i].OriginArn = originArn
	}
	return copies
}

// collectInlineStatements gathers decorated copies of inline policy statements.
func collectInlineStatements(policies []types.InlinePolicy, originArn string) types.PolicyStatementList {
	var stmts types.PolicyStatementList
	for _, policy := range policies {
		decorated := decorateStatements(policy.PolicyDocument.Statement, originArn)
		stmts = append(stmts, decorated...)
	}
	return stmts
}

// collectManagedPolicyStatements gathers decorated copies of attached managed policy statements.
func (ctx *analyzerContext) collectManagedPolicyStatements(attachedPolicies []types.ManagedPolicy) types.PolicyStatementList {
	var stmts types.PolicyStatementList
	for _, attached := range attachedPolicies {
		policy := ctx.policyCache[attached.PolicyArn]
		if policy == nil {
			continue
		}
		doc := policy.DefaultPolicyDocument()
		if doc == nil || doc.Statement == nil {
			continue
		}
		decorated := decorateStatements(doc.Statement, attached.PolicyArn)
		stmts = append(stmts, decorated...)
	}
	return stmts
}

// collectBoundaryStatements returns decorated copies of a permission boundary's statements.
func (ctx *analyzerContext) collectBoundaryStatements(boundary types.ManagedPolicy) types.PolicyStatementList {
	if boundary == (types.ManagedPolicy{}) {
		return nil
	}
	policy := ctx.policyCache[boundary.PolicyArn]
	if policy == nil {
		return nil
	}
	doc := policy.DefaultPolicyDocument()
	if doc == nil || doc.Statement == nil {
		return nil
	}
	return decorateStatements(doc.Statement, boundary.PolicyArn)
}

// collectGroupStatements gathers identity statements from a user's groups.
func (ctx *analyzerContext) collectGroupStatements(groupNames []string) types.PolicyStatementList {
	var stmts types.PolicyStatementList
	for _, groupName := range groupNames {
		group := ctx.getGroupByName(groupName)
		if group == nil {
			continue
		}
		stmts = append(stmts, collectInlineStatements(group.GroupPolicyList, group.Arn)...)
		stmts = append(stmts, ctx.collectManagedPolicyStatements(group.AttachedManagedPolicies)...)
	}
	return stmts
}
