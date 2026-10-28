package escalation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
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
		if !solverConfigsEqual(models[0].Config, m.Config) {
			return nil, fmt.Errorf("MergeModels: all models must have the same solver config (model 0 has %+v, model %d has %+v)", models[0].Config, i+1, m.Config)
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
				if existing := findResource(merged.Resources, r.ARN); existing != nil {
					if existing.Account != r.Account || existing.Type != r.Type {
						slog.Warn("MergeModels: duplicate resource with divergent attributes, keeping first-seen",
							"arn", r.ARN,
							"first_account", existing.Account, "second_account", r.Account,
							"first_type", existing.Type, "second_type", r.Type)
					}
				}
				continue
			}
			seenResources[r.ARN] = true
			merged.Resources = append(merged.Resources, r)
		}

		merged.StructuralFacts = append(merged.StructuralFacts, m.StructuralFacts...)

		for _, rp := range m.ResourcePolicies {
			if seenResourcePolicies[rp.Resource] {
				slog.Warn("MergeModels: duplicate resource policy, keeping first-seen",
					"resource", rp.Resource)
				continue
			}
			seenResourcePolicies[rp.Resource] = true
			merged.ResourcePolicies = append(merged.ResourcePolicies, ResourcePolicy{
				Resource: rp.Resource,
				Policy:   deepCopyPolicy(rp.Policy),
			})
		}

		merged.CollectionErrors = append(merged.CollectionErrors, m.CollectionErrors...)

		switch psType {
		case PermSourcePolicySummary:
			for _, e := range m.PermissionSource.Entries {
				if seenEntries[e.Principal] {
					if existing := findEntry(merged.PermissionSource.Entries, e.Principal); existing != nil {
						if !statementsEqual(existing.EffectiveStatements, e.EffectiveStatements) {
							slog.Warn("MergeModels: duplicate entry with divergent statements, keeping first-seen",
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
				key := tripleKey(&t)
				if seenTriples[key] {
					continue
				}
				seenTriples[key] = true
				merged.PermissionSource.Triples = append(merged.PermissionSource.Triples, t)
			}
		}

		for acctID, cov := range m.CollectionCoverage {
			if cov == nil {
				continue
			}
			if merged.CollectionCoverage == nil {
				merged.CollectionCoverage = make(map[string]*CollectionCoverage)
			}
			if existing, ok := merged.CollectionCoverage[acctID]; ok {
				orMergeCoverage(existing, cov)
			} else {
				c := *cov
				merged.CollectionCoverage[acctID] = &c
			}
		}
	}

	merged.PermissionSource.Type = psType

	return merged, nil
}


func findResource(resources []Resource, arn string) *Resource {
	for i := range resources {
		if resources[i].ARN == arn {
			return &resources[i]
		}
	}
	return nil
}

func statementsEqual(a, b []PolicyStatement) bool {
	if len(a) != len(b) {
		return false
	}
	sa := sortedStatements(a)
	sb := sortedStatements(b)
	ja, errA := json.Marshal(sa)
	jb, errB := json.Marshal(sb)
	if errA != nil || errB != nil {
		return false
	}
	return string(ja) == string(jb)
}

func sortedStatements(s []PolicyStatement) []PolicyStatement {
	out := append([]PolicyStatement(nil), s...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Effect != out[j].Effect {
			return out[i].Effect < out[j].Effect
		}
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}

func tripleKey(t *EvaluatedTriple) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%v", t.Principal, t.Action, t.Target, t.Allowed)
	if len(t.Conditions) > 0 {
		cj, _ := json.Marshal(t.Conditions)
		h.Write(cj)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
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

func deepCopyPolicy(v any) any {
	if v == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("deepCopyPolicy: marshal failed: %v", err))
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		panic(fmt.Sprintf("deepCopyPolicy: unmarshal failed: %v", err))
	}
	return out
}

func orMergeCoverage(dst, src *CollectionCoverage) {
	dv := reflect.ValueOf(dst).Elem()
	sv := reflect.ValueOf(src).Elem()
	for i := 0; i < dv.NumField(); i++ {
		df := dv.Field(i)
		sf := sv.Field(i)
		if df.Kind() == reflect.Bool {
			df.SetBool(df.Bool() || sf.Bool())
		}
	}
}

func copyConditions(src []Condition) []Condition {
	if src == nil {
		return nil
	}
	out := make([]Condition, len(src))
	for i, c := range src {
		out[i] = Condition{
			Key:      c.Key,
			Operator: c.Operator,
			Values:   append([]string(nil), c.Values...),
		}
	}
	return out
}

func solverConfigsEqual(a, b *SolverConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
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
	out.ResourcePolicies = make([]ResourcePolicy, len(m.ResourcePolicies))
	for i, rp := range m.ResourcePolicies {
		out.ResourcePolicies[i] = ResourcePolicy{Resource: rp.Resource, Policy: deepCopyPolicy(rp.Policy)}
	}
	out.CollectionErrors = append([]CollectionError(nil), m.CollectionErrors...)
	out.PermissionSource.Entries = make([]PolicySummaryEntry, len(m.PermissionSource.Entries))
	for i, e := range m.PermissionSource.Entries {
		out.PermissionSource.Entries[i] = PolicySummaryEntry{
			Principal:           e.Principal,
			EffectiveStatements: append([]PolicyStatement(nil), e.EffectiveStatements...),
		}
		for j, s := range e.EffectiveStatements {
			out.PermissionSource.Entries[i].EffectiveStatements[j].Conditions = copyConditions(s.Conditions)
		}
	}
	out.PermissionSource.Triples = make([]EvaluatedTriple, len(m.PermissionSource.Triples))
	for i, t := range m.PermissionSource.Triples {
		out.PermissionSource.Triples[i] = t
		out.PermissionSource.Triples[i].Conditions = copyConditions(t.Conditions)
	}
	out.Config = copySolverConfig(m.Config)
	if m.CollectionCoverage != nil {
		out.CollectionCoverage = make(map[string]*CollectionCoverage, len(m.CollectionCoverage))
		for k, v := range m.CollectionCoverage {
			if v != nil {
				c := *v
				out.CollectionCoverage[k] = &c
			}
		}
	}
	return &out
}

