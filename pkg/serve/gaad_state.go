package serve

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// GaadState implements EvaluatorState by pre-computing the identity and
// boundary policy statements for every principal in the GAAD. This is built
// once at --serve startup and reused for every IPC request.
type GaadState struct {
	// principals maps principal ARN → pre-collected statements.
	principals map[string]principalStatements
}

type principalStatements struct {
	identity *types.PolicyStatementList
	boundary *types.PolicyStatementList
}

// NewGaadState builds a GaadState from the authorization account details.
// It walks users, roles, groups and managed policies to pre-collect every
// principal's identity and boundary statements — the same work
// processUserPermissions / processRolePermissions do in the batch analyzer,
// but cached so each IPC lookup is O(1).
func NewGaadState(gaad *types.AuthorizationAccountDetails, orgPolicies *orgpolicies.OrgPolicies) *GaadState {
	s := &GaadState{
		principals: make(map[string]principalStatements),
	}
	if gaad == nil {
		return s
	}

	// Pre-resolve managed policies by ARN for fast lookup.
	policyDocs := make(map[string]*types.PolicyStatementList)
	gaad.Policies.Range(func(_ string, p types.ManagedPolicyDetail) bool {
		doc := p.DefaultPolicyDocument()
		if doc != nil && doc.Statement != nil {
			stmts := copyStatementsWithOrigin(doc.Statement, p.Arn)
			policyDocs[p.Arn] = &stmts
		}
		return true
	})

	// Helper: collect managed-policy statements
	collectManaged := func(attached []types.ManagedPolicy) types.PolicyStatementList {
		var stmts types.PolicyStatementList
		for _, mp := range attached {
			if s, ok := policyDocs[mp.PolicyArn]; ok {
				stmts = append(stmts, *s...)
			}
		}
		return stmts
	}

	// Helper: collect boundary statements
	collectBoundary := func(boundary types.ManagedPolicy) *types.PolicyStatementList {
		if boundary == (types.ManagedPolicy{}) {
			return nil
		}
		if s, ok := policyDocs[boundary.PolicyArn]; ok {
			cp := make(types.PolicyStatementList, len(*s))
			copy(cp, *s)
			return &cp
		}
		return nil
	}

	// Pre-index group policies by group name
	groupStatements := make(map[string]types.PolicyStatementList)
	gaad.Groups.Range(func(_ string, g types.GroupDetail) bool {
		var stmts types.PolicyStatementList
		// Inline
		for _, p := range g.GroupPolicyList {
			if p.PolicyDocument.Statement != nil {
				stmts = append(stmts, copyStatementsWithOrigin(p.PolicyDocument.Statement, g.Arn)...)
			}
		}
		// Managed
		stmts = append(stmts, collectManaged(g.AttachedManagedPolicies)...)
		groupStatements[g.GroupName] = stmts
		return true
	})

	// Users
	gaad.Users.Range(func(_ string, u types.UserDetail) bool {
		var identity types.PolicyStatementList
		// Inline
		for _, p := range u.UserPolicyList {
			if p.PolicyDocument.Statement != nil {
				identity = append(identity, copyStatementsWithOrigin(p.PolicyDocument.Statement, u.Arn)...)
			}
		}
		// Managed
		identity = append(identity, collectManaged(u.AttachedManagedPolicies)...)
		// Group
		for _, groupName := range u.GroupList {
			if gs, ok := groupStatements[groupName]; ok {
				identity = append(identity, gs...)
			}
		}

		var idPtr *types.PolicyStatementList
		if len(identity) > 0 {
			idPtr = &identity
		}
		s.principals[u.Arn] = principalStatements{
			identity: idPtr,
			boundary: collectBoundary(u.PermissionsBoundary),
		}
		return true
	})

	// Roles
	gaad.Roles.Range(func(_ string, r types.RoleDetail) bool {
		var identity types.PolicyStatementList
		// Inline
		for _, p := range r.RolePolicyList {
			if p.PolicyDocument.Statement != nil {
				identity = append(identity, copyStatementsWithOrigin(p.PolicyDocument.Statement, r.Arn)...)
			}
		}
		// Managed
		identity = append(identity, collectManaged(r.AttachedManagedPolicies)...)

		var idPtr *types.PolicyStatementList
		if len(identity) > 0 {
			idPtr = &identity
		}
		s.principals[r.Arn] = principalStatements{
			identity: idPtr,
			boundary: collectBoundary(r.PermissionsBoundary),
		}
		return true
	})

	return s
}

func (s *GaadState) LookupPrincipalStatements(principalArn string) (identity, boundary *types.PolicyStatementList) {
	p, ok := s.principals[principalArn]
	if !ok {
		return nil, nil
	}
	return p.identity, p.boundary
}

func (s *GaadState) GetResourceAccount(resourceArn string) string {
	parsed, err := arn.Parse(resourceArn)
	if err != nil {
		// For S3-style ARNs without account, try to extract from common patterns
		return ""
	}
	return parsed.AccountID
}

// copyStatementsWithOrigin returns copies of statements with OriginArn set.
// This is a local version of the same function in gaad/statements.go to avoid
// a circular import.
func copyStatementsWithOrigin(stmts *types.PolicyStatementList, originArn string) types.PolicyStatementList {
	if stmts == nil || len(*stmts) == 0 {
		return nil
	}
	out := make(types.PolicyStatementList, len(*stmts))
	copy(out, *stmts)
	for i := range out {
		out[i].OriginArn = originArn
	}
	return out
}

// IsServicePrincipal reports whether a string is a service principal rather
// than an ARN (e.g. "lambda.amazonaws.com").
func IsServicePrincipal(s string) bool {
	return strings.HasSuffix(s, ".amazonaws.com")
}
