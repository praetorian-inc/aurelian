package escalation

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// MergeModels combines multiple per-account Models into a single org-wide
// model suitable for cross-account escalation analysis. All models must use
// the same permission source type.
//
// After merging, root-trust structural facts (arn:aws:iam::ACCOUNT:root)
// are expanded into per-principal trust facts so the solver can match them.
func MergeModels(models []*Model) (*Model, error) {
	if len(models) == 0 {
		return nil, fmt.Errorf("MergeModels: at least one model is required")
	}

	for _, m := range models {
		if m.PermissionSource.Type == PermSourceExternal {
			return nil, fmt.Errorf("MergeModels: external permission source cannot be merged (model uses subprocess command %q)", m.PermissionSource.Command)
		}
	}

	if len(models) == 1 {
		m := models[0]
		m.StructuralFacts = ExpandRootTrustFacts(m.StructuralFacts, m.Principals)
		return m, nil
	}

	psType := models[0].PermissionSource.Type
	for i, m := range models[1:] {
		if m.PermissionSource.Type != psType {
			return nil, fmt.Errorf("MergeModels: all models must have the same permission source type (model 0 has %q, model %d has %q)", psType, i+1, m.PermissionSource.Type)
		}
	}

	merged := &Model{
		Version: models[0].Version,
		Goal:    models[0].Goal,
		Config:  models[0].Config,
	}

	seenAccounts := make(map[string]bool)
	seenPrincipals := make(map[string]bool)

	for _, m := range models {
		for _, a := range m.Accounts {
			if seenAccounts[a.ID] {
				continue
			}
			seenAccounts[a.ID] = true
			merged.Accounts = append(merged.Accounts, a)
		}

		for _, p := range m.Principals {
			if seenPrincipals[p.ARN] {
				continue
			}
			seenPrincipals[p.ARN] = true
			merged.Principals = append(merged.Principals, p)
		}

		merged.Resources = append(merged.Resources, m.Resources...)
		merged.StructuralFacts = append(merged.StructuralFacts, m.StructuralFacts...)
		merged.ResourcePolicies = append(merged.ResourcePolicies, m.ResourcePolicies...)
		merged.CollectionErrors = append(merged.CollectionErrors, m.CollectionErrors...)

		switch psType {
		case PermSourcePolicySummary:
			merged.PermissionSource.Entries = append(merged.PermissionSource.Entries, m.PermissionSource.Entries...)
		case PermSourceEvaluatedTriples:
			merged.PermissionSource.Triples = append(merged.PermissionSource.Triples, m.PermissionSource.Triples...)
		}

		merged.CollectionCoverage = mergeCoverage(merged.CollectionCoverage, m.CollectionCoverage)
	}

	merged.PermissionSource.Type = psType
	merged.StructuralFacts = ExpandRootTrustFacts(merged.StructuralFacts, merged.Principals)

	return merged, nil
}

// mergeCoverage OR-merges two CollectionCoverage structs (true if either is true).
func mergeCoverage(a, b *CollectionCoverage) *CollectionCoverage {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return &CollectionCoverage{
		IAMGAAD:                a.IAMGAAD || b.IAMGAAD,
		EC2InstanceProfiles:    a.EC2InstanceProfiles || b.EC2InstanceProfiles,
		LambdaExecutionRoles:   a.LambdaExecutionRoles || b.LambdaExecutionRoles,
		ECSTaskRoles:           a.ECSTaskRoles || b.ECSTaskRoles,
		CodeBuildServiceRoles:  a.CodeBuildServiceRoles || b.CodeBuildServiceRoles,
		S3BucketPolicies:       a.S3BucketPolicies || b.S3BucketPolicies,
		LambdaResourcePolicies: a.LambdaResourcePolicies || b.LambdaResourcePolicies,
		SQSQueuePolicies:       a.SQSQueuePolicies || b.SQSQueuePolicies,
		KMSKeyPolicies:         a.KMSKeyPolicies || b.KMSKeyPolicies,
		SNSTopicPolicies:       a.SNSTopicPolicies || b.SNSTopicPolicies,
	}
}

// ExpandRootTrustFacts replaces trust_relationship facts that target an
// account root principal (arn:aws:iam::ACCOUNT:root) with per-principal
// trust facts for all roles and users in that account. Groups are excluded
// because they cannot assume roles.
//
// This is necessary because the solver matches trust_relationship facts by
// exact principal ARN. Without expansion, a trust policy that trusts the
// account root would not match any individual principal.
func ExpandRootTrustFacts(facts []StructuralFact, principals []Principal) []StructuralFact {
	accountPrincipals := make(map[string][]string)
	for _, p := range principals {
		if p.Type == PrincipalTypeGroup {
			continue
		}
		accountPrincipals[p.Account] = append(accountPrincipals[p.Account], p.ARN)
	}

	var result []StructuralFact
	for _, f := range facts {
		if f.Type != FactTrustRelationship || !isAccountRootARN(f.To) {
			result = append(result, f)
			continue
		}

		accountID := extractAccountFromRootARN(f.To)
		arns, ok := accountPrincipals[accountID]
		if !ok {
			continue
		}

		for _, principalARN := range arns {
			result = append(result, StructuralFact{
				Type:       FactTrustRelationship,
				From:       f.From,
				To:         principalARN,
				Confidence: f.Confidence,
			})
		}
	}

	return result
}

// isAccountRootARN returns true if the ARN is an account root principal
// (arn:aws:iam::ACCOUNT:root).
func isAccountRootARN(arnStr string) bool {
	parsed, err := arn.Parse(arnStr)
	if err != nil {
		return false
	}
	return parsed.Service == "iam" && parsed.Resource == "root"
}

// extractAccountFromRootARN extracts the account ID from an account root ARN.
func extractAccountFromRootARN(arnStr string) string {
	parsed, err := arn.Parse(arnStr)
	if err != nil {
		return ""
	}
	if parsed.Service == "iam" && parsed.Resource == "root" {
		return parsed.AccountID
	}
	// Fallback: try extracting from arn:aws:iam::ACCOUNT:root pattern
	parts := strings.SplitN(arnStr, ":", 6)
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
