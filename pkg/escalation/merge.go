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
		return copyModel(models[0]), nil
	}

	version := models[0].Version
	psType := models[0].PermissionSource.Type
	goal := models[0].Goal
	for i, m := range models[1:] {
		if m.Version != version {
			return nil, fmt.Errorf("MergeModels: all models must have the same version (model 0 has %q, model %d has %q)", version, i+1, m.Version)
		}
		if m.PermissionSource.Type != psType {
			return nil, fmt.Errorf("MergeModels: all models must have the same permission source type (model 0 has %q, model %d has %q)", psType, i+1, m.PermissionSource.Type)
		}
		if m.Goal != goal {
			return nil, fmt.Errorf("MergeModels: all models must have the same goal (model 0 has %+v, model %d has %+v)", goal, i+1, m.Goal)
		}
	}

	merged := &Model{
		Version: version,
		Goal:    models[0].Goal,
		Config:  copySolverConfig(models[0].Config),
	}

	seenAccounts := make(map[string]bool)
	seenPrincipals := make(map[string]bool)
	seenResources := make(map[string]bool)
	seenResourcePolicies := make(map[string]bool)
	seenEntries := make(map[string]bool)
	seenTriples := make(map[string]bool)

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

		for _, r := range m.Resources {
			if seenResources[r.ARN] {
				continue
			}
			seenResources[r.ARN] = true
			merged.Resources = append(merged.Resources, r)
		}

		merged.StructuralFacts = append(merged.StructuralFacts, m.StructuralFacts...)

		for _, rp := range m.ResourcePolicies {
			if seenResourcePolicies[rp.Resource] {
				continue
			}
			seenResourcePolicies[rp.Resource] = true
			merged.ResourcePolicies = append(merged.ResourcePolicies, rp)
		}

		merged.CollectionErrors = append(merged.CollectionErrors, m.CollectionErrors...)

		switch psType {
		case PermSourcePolicySummary:
			for _, e := range m.PermissionSource.Entries {
				if seenEntries[e.Principal] {
					if existing := findEntry(merged.PermissionSource.Entries, e.Principal); existing != nil {
						if len(existing.EffectiveStatements) != len(e.EffectiveStatements) {
							slog.Warn("MergeModels: duplicate entry with divergent statement count, keeping first-seen",
								"principal", e.Principal,
								"first_statements", len(existing.EffectiveStatements),
								"second_statements", len(e.EffectiveStatements))
						}
					}
					continue
				}
				seenEntries[e.Principal] = true
				merged.PermissionSource.Entries = append(merged.PermissionSource.Entries, e)
			}
		case PermSourceEvaluatedTriples:
			for _, t := range m.PermissionSource.Triples {
				key := t.Principal + "\x00" + t.Action + "\x00" + t.Target + "\x00" + fmt.Sprintf("%v", t.Allowed)
				if seenTriples[key] {
					continue
				}
				seenTriples[key] = true
				merged.PermissionSource.Triples = append(merged.PermissionSource.Triples, t)
			}
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

func findEntry(entries []PolicySummaryEntry, principal string) *PolicySummaryEntry {
	for i := range entries {
		if entries[i].Principal == principal {
			return &entries[i]
		}
	}
	return nil
}

func findPrincipal(principals []Principal, arn string) *Principal {
	for i := range principals {
		if principals[i].ARN == arn {
			return &principals[i]
		}
	}
	return nil
}

func copySolverConfig(cfg *SolverConfig) *SolverConfig {
	if cfg == nil {
		return nil
	}
	c := *cfg
	return &c
}

func copyModel(m *Model) *Model {
	out := *m
	out.Accounts = append([]Account(nil), m.Accounts...)
	out.Principals = append([]Principal(nil), m.Principals...)
	out.Resources = append([]Resource(nil), m.Resources...)
	out.StructuralFacts = append([]StructuralFact(nil), m.StructuralFacts...)
	out.ResourcePolicies = append([]ResourcePolicy(nil), m.ResourcePolicies...)
	out.CollectionErrors = append([]CollectionError(nil), m.CollectionErrors...)
	out.PermissionSource.Entries = append([]PolicySummaryEntry(nil), m.PermissionSource.Entries...)
	out.PermissionSource.Triples = append([]EvaluatedTriple(nil), m.PermissionSource.Triples...)
	out.Config = copySolverConfig(m.Config)
	if m.CollectionCoverage != nil {
		c := *m.CollectionCoverage
		out.CollectionCoverage = &c
	}
	return &out
}

