package escalation

import (
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AssembleInput holds the collected data for model assembly.
type AssembleInput struct {
	GAAD        *types.AuthorizationAccountDetails
	OrgPolicies *orgpolicies.OrgPolicies
	Resources   store.Map[output.AWSResource]
	Coverage    *CoverageTracker

	// Relationships holds the evaluated IAM permission edges from the analyzer.
	// Required when PermissionFormat is "evaluated_triples"; ignored otherwise.
	Relationships store.Map[output.AWSIAMRelationship]

	// PermissionFormat controls the permission_source type.
	// Supported: "policy_summary" (default), "evaluated_triples".
	PermissionFormat string
}

// Assemble builds a complete model-v1 Model from collected data.
// The returned model is ready for JSON serialization.
func Assemble(in AssembleInput) *Model {
	m := &Model{
		Version:          "1.0",
		Principals:       CollectPrincipals(in.GAAD),
		Resources:        CollectResources(in.Resources),
		StructuralFacts:  CollectStructuralFacts(in.GAAD, in.Resources),
		ResourcePolicies: CollectResourcePolicies(in.Resources),
		Accounts:         collectAccounts(in.GAAD),
		Goal: Goal{
			Type:     GoalReachAdmin,
			Attacker: pickFirstPrincipal(in.GAAD),
		},
	}

	if in.Coverage != nil {
		m.CollectionCoverage = in.Coverage.Build()
	}

	switch in.PermissionFormat {
	case "evaluated_triples":
		m.PermissionSource = PermissionSource{
			Type:    PermSourceEvaluatedTriples,
			Triples: collectEvaluatedTriples(in.Relationships),
		}
	default: // "policy_summary" is the default
		m.PermissionSource = PermissionSource{
			Type: PermSourcePolicySummary,
			Entries: CollectPolicySummary(PolicySummaryInput{
				GAAD:        in.GAAD,
				OrgPolicies: in.OrgPolicies,
				Resources:   in.Resources,
			}),
		}
	}

	return m
}

// collectAccounts extracts the unique account ID from GAAD.
func collectAccounts(gaad *types.AuthorizationAccountDetails) []Account {
	if gaad.AccountID == "" {
		return nil
	}
	return []Account{{ID: gaad.AccountID}}
}

// pickFirstPrincipal returns the ARN of the first principal found. Used as a
// default attacker when none is specified. The solver requires a valid attacker
// ARN; the user is expected to override this.
func pickFirstPrincipal(gaad *types.AuthorizationAccountDetails) string {
	var first string
	gaad.Users.Range(func(_ string, u types.UserDetail) bool {
		first = u.Arn
		return false
	})
	if first != "" {
		return first
	}
	gaad.Roles.Range(func(_ string, r types.RoleDetail) bool {
		first = r.Arn
		return false
	})
	return first
}

// collectEvaluatedTriples converts the analyzer's AWSIAMRelationship edges
// into solver-format EvaluatedTriple entries.
func collectEvaluatedTriples(relationships store.Map[output.AWSIAMRelationship]) []EvaluatedTriple {
	if relationships.Len() == 0 {
		return nil
	}
	var triples []EvaluatedTriple
	relationships.Range(func(_ string, rel output.AWSIAMRelationship) bool {
		triples = append(triples, EvaluatedTriple{
			Principal: rel.Principal.ARN,
			Action:    rel.Action,
			Target:    rel.Resource.ARN,
			Allowed:   true, // relationships are pre-filtered to allowed-only
		})
		return true
	})
	return triples
}
