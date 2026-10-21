package escalation

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// PolicySummaryInput holds all data needed to build the policy summary.
type PolicySummaryInput struct {
	GAAD        *types.AuthorizationAccountDetails
	OrgPolicies *orgpolicies.OrgPolicies
	Resources   store.Map[output.AWSResource]
}

// CollectPolicySummary builds PolicySummaryEntry for each principal by collapsing
// identity policies (inline + managed), permission boundaries, SCPs, and
// resource-policy grants into effective_statements per the spec (section 3.4).
func CollectPolicySummary(in PolicySummaryInput) []PolicySummaryEntry {
	var entries []PolicySummaryEntry

	// Build an index of resource policies that grant access to specific principals.
	resourcePolicyGrants := indexResourcePolicyGrants(in.Resources)
	groupsByName := BuildGroupsByName(in.GAAD)

	in.GAAD.Users.Range(func(_ string, u types.UserDetail) bool {
		stmts := collectUserEffectiveStatements(u, in.GAAD, groupsByName)
		stmts = append(stmts, scpStatements(u.Arn, in.OrgPolicies)...)
		stmts = append(stmts, resourcePolicyGrants[u.Arn]...)
		entries = append(entries, PolicySummaryEntry{
			Principal:           u.Arn,
			EffectiveStatements: ensureNonNil(stmts),
		})
		return true
	})

	in.GAAD.Roles.Range(func(_ string, r types.RoleDetail) bool {
		stmts := collectRoleEffectiveStatements(r, in.GAAD)
		stmts = append(stmts, scpStatements(r.Arn, in.OrgPolicies)...)
		stmts = append(stmts, resourcePolicyGrants[r.Arn]...)
		entries = append(entries, PolicySummaryEntry{
			Principal:           r.Arn,
			EffectiveStatements: ensureNonNil(stmts),
		})
		return true
	})

	in.GAAD.Groups.Range(func(_ string, g types.GroupDetail) bool {
		stmts := collectGroupEffectiveStatements(g, in.GAAD)
		stmts = append(stmts, resourcePolicyGrants[g.Arn]...)
		entries = append(entries, PolicySummaryEntry{
			Principal:           g.Arn,
			EffectiveStatements: ensureNonNil(stmts),
		})
		return true
	})

	return entries
}

// collectGroupEffectiveStatements gathers all identity statements for a group
// (inline, managed). The solver uses these for the add_user_to_group rule.
func collectGroupEffectiveStatements(group types.GroupDetail, gaad *types.AuthorizationAccountDetails) []PolicyStatement {
	var stmts []PolicyStatement
	for _, p := range group.GroupPolicyList {
		source := fmt.Sprintf("group-inline:%s/%s", group.GroupName, p.PolicyName)
		stmts = append(stmts, flattenStatements(p.PolicyDocument.Statement, source)...)
	}
	for _, mp := range group.AttachedManagedPolicies {
		stmts = append(stmts, managedPolicyStatements(gaad, mp)...)
	}
	return stmts
}

// scpStatements extracts SCP statements for the principal's account and returns
// them as solver-format PolicyStatements. Returns nil if no SCPs apply.
func scpStatements(principalArn string, orgPolicies *orgpolicies.OrgPolicies) []PolicyStatement {
	if orgPolicies == nil {
		return nil
	}
	parsed, err := arn.Parse(principalArn)
	if err != nil {
		return nil
	}
	scps := orgPolicies.GetAllScpPoliciesForTarget(parsed.AccountID)
	if scps == nil || len(*scps) == 0 {
		return nil
	}
	return flattenStatements(scps, "scp")
}

// indexResourcePolicyGrants scans all resource policies and builds a map of
// principal ARN → PolicyStatements for grants found in resource policies.
// This covers spec section 3.4 point 5: resource-policy-only grants.
func indexResourcePolicyGrants(resources store.Map[output.AWSResource]) map[string][]PolicyStatement {
	grants := make(map[string][]PolicyStatement)
	resources.Range(func(_ string, r output.AWSResource) bool {
		if r.ResourcePolicy == nil || r.ResourcePolicy.Statement == nil {
			return true
		}
		for _, stmt := range *r.ResourcePolicy.Statement {
			if !strings.EqualFold(stmt.Effect, "Allow") {
				continue
			}
			principals := stmt.ExtractPrincipals()
			if len(principals) == 0 {
				continue
			}
			actions := expandStmtActions(&stmt)
			resources := expandStmtResources(&stmt)
			conditions := convertConditions(stmt.Condition)
			source := fmt.Sprintf("resource_policy:%s", r.ARN)

			for _, principal := range principals {
				if principal == "" || principal == "*" {
					continue // skip wildcard principals — too noisy
				}
				for _, action := range actions {
					for _, resource := range resources {
						grants[principal] = append(grants[principal], PolicyStatement{
							Effect:     "Allow",
							Action:     action,
							Resource:   resource,
							Source:     source,
							Conditions: conditions,
						})
					}
				}
			}
		}
		return true
	})
	return grants
}

// collectUserEffectiveStatements gathers all identity statements for a user
// (inline, managed, group) plus permission boundary statements.
func collectUserEffectiveStatements(user types.UserDetail, gaad *types.AuthorizationAccountDetails, groupsByName map[string]types.GroupDetail) []PolicyStatement {
	var stmts []PolicyStatement

	// Inline policies
	for _, p := range user.UserPolicyList {
		source := fmt.Sprintf("inline:%s/%s", user.UserName, p.PolicyName)
		stmts = append(stmts, flattenStatements(p.PolicyDocument.Statement, source)...)
	}

	// Managed policies
	for _, mp := range user.AttachedManagedPolicies {
		stmts = append(stmts, managedPolicyStatements(gaad, mp)...)
	}

	// Group policies
	for _, groupName := range user.GroupList {
		g, ok := groupsByName[groupName]
		if !ok {
			continue
		}
		for _, p := range g.GroupPolicyList {
			source := fmt.Sprintf("group:%s/inline:%s", g.GroupName, p.PolicyName)
			stmts = append(stmts, flattenStatements(p.PolicyDocument.Statement, source)...)
		}
		for _, mp := range g.AttachedManagedPolicies {
			stmts = append(stmts, managedPolicyStatements(gaad, mp)...)
		}
	}

	// Permission boundary
	if user.PermissionsBoundary.PolicyArn != "" {
		stmts = append(stmts, boundaryStatements(gaad, user.PermissionsBoundary)...)
	}

	return stmts
}

// collectRoleEffectiveStatements gathers all identity statements for a role
// (inline, managed) plus permission boundary statements.
func collectRoleEffectiveStatements(role types.RoleDetail, gaad *types.AuthorizationAccountDetails) []PolicyStatement {
	var stmts []PolicyStatement

	// Inline policies
	for _, p := range role.RolePolicyList {
		source := fmt.Sprintf("inline:%s/%s", role.RoleName, p.PolicyName)
		stmts = append(stmts, flattenStatements(p.PolicyDocument.Statement, source)...)
	}

	// Managed policies
	for _, mp := range role.AttachedManagedPolicies {
		stmts = append(stmts, managedPolicyStatements(gaad, mp)...)
	}

	// Permission boundary
	if role.PermissionsBoundary.PolicyArn != "" {
		stmts = append(stmts, boundaryStatements(gaad, role.PermissionsBoundary)...)
	}

	return stmts
}

// managedPolicyStatements resolves a managed policy attachment to flat statements.
func managedPolicyStatements(gaad *types.AuthorizationAccountDetails, mp types.ManagedPolicy) []PolicyStatement {
	stmts := gaad.ResolveManagedPolicyStatements(mp.PolicyArn)
	if stmts == nil {
		return nil
	}
	source := fmt.Sprintf("managed:%s", mp.PolicyArn)
	return flattenStatements(stmts, source)
}

// boundaryStatements converts a permission boundary into solver-format statements.
func boundaryStatements(gaad *types.AuthorizationAccountDetails, boundary types.ManagedPolicy) []PolicyStatement {
	stmts := gaad.ResolveManagedPolicyStatements(boundary.PolicyArn)
	if stmts == nil {
		return nil
	}
	source := fmt.Sprintf("boundary:%s", boundary.PolicyArn)
	return flattenStatements(stmts, source)
}

// flattenStatements converts AWS PolicyStatements into the solver's flat format.
// Each (action, resource) pair in a statement becomes a separate PolicyStatement
// so the solver can evaluate them individually.
func flattenStatements(stmts *types.PolicyStatementList, source string) []PolicyStatement {
	if stmts == nil {
		return nil
	}
	var result []PolicyStatement
	for _, stmt := range *stmts {
		actions := expandStmtActions(&stmt)
		resources := expandStmtResources(&stmt)
		conditions := convertConditions(stmt.Condition)

		for _, action := range actions {
			for _, resource := range resources {
				result = append(result, PolicyStatement{
					Effect:     normalizeEffect(stmt.Effect),
					Action:     action,
					Resource:   resource,
					Source:     source,
					Conditions: conditions,
				})
			}
		}
	}
	return result
}

// expandStmtActions returns all action patterns from a statement.
// For NotAction, we emit a special "NotAction:..." prefix that the solver
// understands as an inverse match.
func expandStmtActions(stmt *types.PolicyStatement) []string {
	if stmt.Action != nil {
		return []string(*stmt.Action)
	}
	if stmt.NotAction != nil {
		actions := make([]string, len(*stmt.NotAction))
		for i, a := range *stmt.NotAction {
			actions[i] = "NotAction:" + a
		}
		return actions
	}
	return []string{"*"}
}

// expandStmtResources returns all resource patterns from a statement.
// NotResource is treated conservatively as "*" (applies to everything) because
// the solver cannot natively evaluate inverse resource matching and the
// conservative interpretation avoids false negatives.
func expandStmtResources(stmt *types.PolicyStatement) []string {
	if stmt.Resource != nil {
		return []string(*stmt.Resource)
	}
	if stmt.NotResource != nil {
		return []string{"*"}
	}
	return []string{"*"}
}

// convertConditions transforms AWS IAM conditions into the solver's format.
func convertConditions(cond *types.Condition) []Condition {
	if cond == nil {
		return nil
	}
	var result []Condition
	for operator, condStmt := range *cond {
		for key, values := range condStmt {
			result = append(result, Condition{
				Key:      key,
				Operator: operator,
				Values:   []string(values),
			})
		}
	}
	return result
}

// ensureNonNil returns the slice as-is if non-nil, otherwise returns an
// initialized empty slice. This ensures JSON serialization emits [] not null.
func ensureNonNil(stmts []PolicyStatement) []PolicyStatement {
	if stmts == nil {
		return []PolicyStatement{}
	}
	return stmts
}

func normalizeEffect(effect string) string {
	if strings.EqualFold(effect, "allow") {
		return "Allow"
	}
	return "Deny"
}
