package escalation

import "github.com/praetorian-inc/aurelian/pkg/types"

// ---------------------------------------------------------------------------
// PolicyOrigin describes where a statement came from.
// ---------------------------------------------------------------------------

// OriginType classifies the source of a policy statement.
type OriginType string

const (
	// OriginInline is an inline policy embedded on the principal.
	OriginInline OriginType = "inline"
	// OriginManaged is a customer- or AWS-managed policy attached to the principal.
	OriginManaged OriginType = "managed"
)

// PolicyOrigin carries provenance metadata for a single statement. Callers
// that need a source label (e.g. "inline:alice/my-policy") can build it from
// these fields; callers that only need raw statements can ignore the origin.
type PolicyOrigin struct {
	// Type is OriginInline or OriginManaged.
	Type OriginType
	// PrincipalType is "user", "role", or "group".
	PrincipalType string
	// PrincipalName is the human-readable name of the principal
	// (UserName / RoleName / GroupName).
	PrincipalName string
	// PolicyName is the inline policy name or managed policy name.
	PolicyName string
	// PolicyARN is set for managed policies.
	PolicyARN string
}

// ---------------------------------------------------------------------------
// ManagedPolicyResolver abstracts how managed policy ARNs are resolved to
// their default policy document. This decouples the walk from a concrete
// GAAD pointer, making it testable and reusable across packages.
// ---------------------------------------------------------------------------

// ManagedPolicyResolver resolves a managed policy ARN to the statements in its
// default version. Returns nil if the policy is not found or has no default
// version.
type ManagedPolicyResolver func(policyARN string) *types.PolicyStatementList

// GAADPolicyResolver returns a ManagedPolicyResolver backed by a GAAD's
// Policies map. This is the production resolver.
func GAADPolicyResolver(gaad *types.AuthorizationAccountDetails) ManagedPolicyResolver {
	return func(policyARN string) *types.PolicyStatementList {
		policy, ok := gaad.Policies.Get(policyARN)
		if !ok {
			return nil
		}
		doc := policy.DefaultPolicyDocument()
		if doc == nil || doc.Statement == nil {
			return nil
		}
		return doc.Statement
	}
}

// ---------------------------------------------------------------------------
// StatementVisitor is the callback signature for Walk* functions.
// ---------------------------------------------------------------------------

// StatementVisitor is called once per statement with its origin metadata.
type StatementVisitor func(origin PolicyOrigin, stmt types.PolicyStatement)

// ---------------------------------------------------------------------------
// Walk functions: traverse identity statements for each principal type.
// ---------------------------------------------------------------------------

// walkInlineStatements iterates inline policy statements and calls visit for
// each one.
func walkInlineStatements(
	principalType, principalName string,
	policies []types.InlinePolicy,
	visit StatementVisitor,
) {
	for _, p := range policies {
		if p.PolicyDocument.Statement == nil {
			continue
		}
		origin := PolicyOrigin{
			Type:          OriginInline,
			PrincipalType: principalType,
			PrincipalName: principalName,
			PolicyName:    p.PolicyName,
		}
		for _, s := range *p.PolicyDocument.Statement {
			visit(origin, s)
		}
	}
}

// walkManagedStatements iterates attached managed policy statements and calls
// visit for each one.
func walkManagedStatements(
	principalType, principalName string,
	attached []types.ManagedPolicy,
	resolve ManagedPolicyResolver,
	visit StatementVisitor,
) {
	for _, mp := range attached {
		stmts := resolve(mp.PolicyArn)
		if stmts == nil {
			continue
		}
		origin := PolicyOrigin{
			Type:          OriginManaged,
			PrincipalType: principalType,
			PrincipalName: principalName,
			PolicyName:    mp.PolicyName,
			PolicyARN:     mp.PolicyArn,
		}
		for _, s := range *stmts {
			visit(origin, s)
		}
	}
}

// WalkRoleStatements walks all identity statements (inline + managed) for a role.
func WalkRoleStatements(role *types.RoleDetail, resolve ManagedPolicyResolver, visit StatementVisitor) {
	walkInlineStatements("role", role.RoleName, role.RolePolicyList, visit)
	walkManagedStatements("role", role.RoleName, role.AttachedManagedPolicies, resolve, visit)
}

// WalkGroupStatements walks all identity statements (inline + managed) for a group.
func WalkGroupStatements(group *types.GroupDetail, resolve ManagedPolicyResolver, visit StatementVisitor) {
	walkInlineStatements("group", group.GroupName, group.GroupPolicyList, visit)
	walkManagedStatements("group", group.GroupName, group.AttachedManagedPolicies, resolve, visit)
}

// WalkUserStatements walks all identity statements for a user: inline policies,
// attached managed policies, and group policies (inline + managed for each group
// in the user's GroupList).
func WalkUserStatements(
	user *types.UserDetail,
	groupsByName map[string]types.GroupDetail,
	resolve ManagedPolicyResolver,
	visit StatementVisitor,
) {
	walkInlineStatements("user", user.UserName, user.UserPolicyList, visit)
	walkManagedStatements("user", user.UserName, user.AttachedManagedPolicies, resolve, visit)

	for _, groupName := range user.GroupList {
		g, ok := groupsByName[groupName]
		if !ok {
			continue
		}
		WalkGroupStatements(&g, resolve, visit)
	}
}

// ---------------------------------------------------------------------------
// Convenience collectors: return raw []types.PolicyStatement slices.
// These replace the old collectAll*Statements helpers in build.go and the
// collect*Statements methods in subprocess/evaluator.go.
// ---------------------------------------------------------------------------

// CollectRawRoleStatements collects all raw identity statements for a role.
func CollectRawRoleStatements(role *types.RoleDetail, resolve ManagedPolicyResolver) []types.PolicyStatement {
	var stmts []types.PolicyStatement
	WalkRoleStatements(role, resolve, func(_ PolicyOrigin, s types.PolicyStatement) {
		stmts = append(stmts, s)
	})
	return stmts
}

// CollectRawGroupStatements collects all raw identity statements for a group.
func CollectRawGroupStatements(group *types.GroupDetail, resolve ManagedPolicyResolver) []types.PolicyStatement {
	var stmts []types.PolicyStatement
	WalkGroupStatements(group, resolve, func(_ PolicyOrigin, s types.PolicyStatement) {
		stmts = append(stmts, s)
	})
	return stmts
}

// CollectRawUserStatements collects all raw identity statements for a user,
// including group policies.
func CollectRawUserStatements(
	user *types.UserDetail,
	groupsByName map[string]types.GroupDetail,
	resolve ManagedPolicyResolver,
) []types.PolicyStatement {
	var stmts []types.PolicyStatement
	WalkUserStatements(user, groupsByName, resolve, func(_ PolicyOrigin, s types.PolicyStatement) {
		stmts = append(stmts, s)
	})
	return stmts
}
