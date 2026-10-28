package escalation

import (
	"fmt"
	"log/slog"
)

// MergeModels combines multiple per-account Models into a single org-wide
// model suitable for cross-account escalation analysis. All models must use
// the same permission source type. Root-trust facts (arn:aws:iam::ACCOUNT:root)
// are preserved as-is for solver-side interpretation.
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
		m := *models[0]
		return &m, nil
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
				if existing := findPrincipal(merged.Principals, p.ARN); existing != nil {
					if existing.IsAdmin != p.IsAdmin || existing.Type != p.Type {
						slog.Warn("MergeModels: duplicate principal with divergent attributes, keeping first-seen",
							"arn", p.ARN,
							"first_is_admin", existing.IsAdmin, "second_is_admin", p.IsAdmin,
							"first_type", existing.Type, "second_type", p.Type)
					}
				}
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

	return merged, nil
}

// mergeCoverage OR-merges two CollectionCoverage structs (true if either is true).
func mergeCoverage(a, b *CollectionCoverage) *CollectionCoverage {
	if a == nil && b == nil {
		return nil
	}
	if a == nil {
		c := *b
		return &c
	}
	if b == nil {
		c := *a
		return &c
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

func findPrincipal(principals []Principal, arn string) *Principal {
	for i := range principals {
		if principals[i].ARN == arn {
			return &principals[i]
		}
	}
	return nil
}

