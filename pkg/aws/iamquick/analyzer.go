package iamquick

import (
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// Analyzer performs quick IAM privilege escalation and trust relationship analysis
// on GAAD data without requiring a full graph evaluation.
type Analyzer struct {
	gaad *types.AuthorizationAccountDetails
}

// NewAnalyzer creates an Analyzer for the given GAAD data.
func NewAnalyzer(gaad *types.AuthorizationAccountDetails) *Analyzer {
	return &Analyzer{gaad: gaad}
}

// Findings holds all analysis results grouped by type for structured output.
type Findings struct {
	Privesc map[string][]output.AWSResource // keyed by privesc combo name
	Trusts  map[string][]output.AWSResource // keyed by trust type
}

// Analyze runs privesc scanning and trust analysis, emitting findings to out.
func (a *Analyzer) Analyze(out *pipeline.P[model.AurelianModel]) {
	a.scanPrivescs(out)
	a.analyzeTrusts(out)
}

// Collect runs the full analysis and returns findings grouped by type
// instead of sending them through a pipeline.
func (a *Analyzer) Collect() *Findings {
	f := &Findings{
		Privesc: make(map[string][]output.AWSResource),
		Trusts:  make(map[string][]output.AWSResource),
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		a.Analyze(out)
		out.Close()
	}()

	for m := range out.Range() {
		r, ok := m.(output.AWSResource)
		if !ok {
			continue
		}
		switch r.Properties["finding_type"] {
		case "privesc":
			name := r.Properties["privesc_type"].(string)
			f.Privesc[name] = append(f.Privesc[name], r)
		case "trust":
			name := r.Properties["trust_type"].(string)
			f.Trusts[name] = append(f.Trusts[name], r)
		}
	}
	return f
}

// scanPrivescs checks every user and role for privilege escalation combinations.
func (a *Analyzer) scanPrivescs(out *pipeline.P[model.AurelianModel]) {
	lookupPolicy := a.policyLookup()

	a.gaad.Users.Range(func(_ string, user types.UserDetail) bool {
		policies := a.collectUserPolicies(user, lookupPolicy)
		allowed, denied := collectActions(policies)
		a.checkCombinations(user.Arn, "AWS::IAM::User", allowed, denied, out)
		return true
	})

	a.gaad.Roles.Range(func(_ string, role types.RoleDetail) bool {
		policies := collectPolicies(role.RolePolicyList, role.AttachedManagedPolicies, lookupPolicy)
		allowed, denied := collectActions(policies)
		a.checkCombinations(role.Arn, "AWS::IAM::Role", allowed, denied, out)
		return true
	})
}

// collectUserPolicies gathers all policies for a user: inline, managed, and group policies.
func (a *Analyzer) collectUserPolicies(user types.UserDetail, lookupPolicy func(string) *types.Policy) []types.Policy {
	policies := collectPolicies(user.UserPolicyList, user.AttachedManagedPolicies, lookupPolicy)

	// Resolve group policies — only from groups in the same account.
	userAccountID := extractAccountID(user.Arn)
	for _, groupName := range user.GroupList {
		a.gaad.Groups.Range(func(_ string, group types.GroupDetail) bool {
			if group.GroupName != groupName {
				return true
			}
			if extractAccountID(group.Arn) != userAccountID {
				return true
			}
			policies = append(policies, collectPolicies(group.GroupPolicyList, group.AttachedManagedPolicies, lookupPolicy)...)
			return false // found the group, stop searching
		})
	}
	return policies
}

// policyLookup returns a function that resolves a managed policy ARN to its
// default policy document from the GAAD data.
func (a *Analyzer) policyLookup() func(string) *types.Policy {
	return func(arn string) *types.Policy {
		mp, ok := a.gaad.Policies.Get(arn)
		if !ok {
			return nil
		}
		return mp.DefaultPolicyDocument()
	}
}

// actionGroup represents one or more action patterns from a single policy statement.
// For regular Action fields, each pattern gets its own group (notAction=false).
// For NotAction fields, all patterns are grouped together (notAction=true) because
// the semantics require checking the full list: "everything except ALL of these".
type actionGroup struct {
	patterns  []string
	notAction bool
}

// collectActions iterates policy statements and returns separate sets of
// allowed and denied action groups. Handles both Action and NotAction fields.
func collectActions(policies []types.Policy) (allowed, denied []actionGroup) {
	for _, pol := range policies {
		if pol.Statement == nil {
			continue
		}
		for _, stmt := range *pol.Statement {
			isAllow := strings.EqualFold(stmt.Effect, "Allow")
			isDeny := strings.EqualFold(stmt.Effect, "Deny")
			if !isAllow && !isDeny {
				continue
			}
			target := &allowed
			if isDeny {
				target = &denied
			}
			if stmt.Action != nil {
				for _, a := range *stmt.Action {
					*target = append(*target, actionGroup{patterns: []string{a}})
				}
			}
			if stmt.NotAction != nil {
				*target = append(*target, actionGroup{
					patterns:  []string(*stmt.NotAction),
					notAction: true,
				})
			}
		}
	}
	return allowed, denied
}

// checkCombinations tests whether a principal has all actions for any privesc combo.
func (a *Analyzer) checkCombinations(
	principalARN, resourceType string,
	allowed, denied []actionGroup,
	out *pipeline.P[model.AurelianModel],
) {
	for _, combo := range privescCombinations {
		if hasAllActions(combo.Actions, allowed, denied) {
			out.Send(output.AWSResource{
				ResourceType: resourceType,
				ResourceID:   principalARN,
				ARN:          principalARN,
				AccountRef:   a.gaad.AccountID,
				Properties: map[string]any{
					"finding_type":    "privesc",
					"privesc_type":    combo.Name,
					"matched_actions": combo.Actions,
				},
			})
		}
	}
}

// hasAllActions returns true if every action in the combo is allowed and not denied.
func hasAllActions(comboActions []string, allowed, denied []actionGroup) bool {
	for _, target := range comboActions {
		if !isActionAllowed(target, allowed, denied) {
			return false
		}
	}
	return true
}

// isActionAllowed checks if a target action is granted by allowed groups
// and not revoked by denied groups.
func isActionAllowed(target string, allowed, denied []actionGroup) bool {
	for _, d := range denied {
		if d.notAction {
			// NotAction Deny: denies everything except the listed actions.
			// Action is denied only if it matches NONE of the exception patterns.
			if !matchesAnyPattern(d.patterns, target) {
				return false
			}
		} else if matchesAnyPattern(d.patterns, target) {
			return false
		}
	}
	for _, a := range allowed {
		if a.notAction {
			// NotAction Allow: allows everything except the listed actions.
			// Action is allowed only if it matches NONE of the exception patterns.
			if !matchesAnyPattern(a.patterns, target) {
				return true
			}
		} else if matchesAnyPattern(a.patterns, target) {
			return true
		}
	}
	return false
}

// matchesAnyPattern returns true if target matches any of the given patterns.
func matchesAnyPattern(patterns []string, target string) bool {
	for _, p := range patterns {
		if iam.MatchesPattern(p, target) {
			return true
		}
	}
	return false
}

// extractAccountID returns the account ID from an ARN.
func extractAccountID(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
