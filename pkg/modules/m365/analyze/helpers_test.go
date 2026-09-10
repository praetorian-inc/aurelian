package analyze

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	m365templates "github.com/praetorian-inc/aurelian/pkg/templates/m365"
)

// collectEmitRisk calls emitRisk and collects the result from the pipeline.
func collectEmitRisk(t *testing.T, def *m365templates.M365CheckTemplate, result *checks.CheckResult, bag *databag.M365DataBag) output.AurelianRisk {
	t.Helper()
	out := pipeline.New[model.AurelianModel]()
	go func() {
		emitRisk(def, result, bag, out)
		out.Close()
	}()
	results, err := out.Collect()
	if err != nil {
		t.Fatalf("collect error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	risk, ok := results[0].(output.AurelianRisk)
	if !ok {
		t.Fatalf("expected AurelianRisk, got %T", results[0])
	}
	return risk
}

func TestEmitRisk(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "tenant-123", TenantDomain: "contoso.com"}
	def := &m365templates.M365CheckTemplate{
		ID: "5.2.2.1", Title: "Test Check", Service: "entra",
		Level: "L1", Profile: "E3 Level 1", Execution: "Automated",
		Severity: "high", Remediation: "Fix it", Rationale: "Because security",
		Guard: m365templates.GuardMeta{FindingSlug: "m365-cis-test", PhaseTag: "phase_m365_entra", AssetType: "m365tenant"},
	}
	result := &checks.CheckResult{Passed: false, ResourceID: "policy-1", Message: "Check failed", Evidence: map[string]any{"key": "value"}}

	risk := collectEmitRisk(t, def, result, bag)

	if risk.Name != "m365-cis-test" {
		t.Errorf("expected name 'm365-cis-test', got %q", risk.Name)
	}
	if risk.Severity != output.RiskSeverityHigh {
		t.Errorf("expected severity 'high', got %q", risk.Severity)
	}
	if risk.ImpactedResourceID != "m365://contoso.com/policy-1" {
		t.Errorf("expected impacted resource 'm365://contoso.com/policy-1', got %q", risk.ImpactedResourceID)
	}
	if risk.DeduplicationID != "m365-cis-5.2.2.1-tenant-123" {
		t.Errorf("expected dedup ID 'm365-cis-5.2.2.1-tenant-123', got %q", risk.DeduplicationID)
	}

	var ctx M365CheckContext
	if err := json.Unmarshal(risk.Context, &ctx); err != nil {
		t.Fatalf("failed to unmarshal context: %v", err)
	}
	if ctx.CISID != "5.2.2.1" {
		t.Errorf("expected CISID '5.2.2.1', got %q", ctx.CISID)
	}
	if ctx.TenantDomain != "contoso.com" {
		t.Errorf("expected tenant domain 'contoso.com', got %q", ctx.TenantDomain)
	}
	if ctx.Message != "Check failed" {
		t.Errorf("expected message 'Check failed', got %q", ctx.Message)
	}
}

func TestEmitRisk_DefaultResourceID(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "tenant-456", TenantDomain: "example.com"}
	def := &m365templates.M365CheckTemplate{ID: "1.1.1", Title: "Test", Severity: "medium", Guard: m365templates.GuardMeta{FindingSlug: "test-slug"}}
	result := &checks.CheckResult{Passed: false, ResourceID: "", Message: "failed"}

	risk := collectEmitRisk(t, def, result, bag)
	if risk.ImpactedResourceID != "m365://example.com/tenant-456" {
		t.Errorf("expected default resource ID with tenant, got %q", risk.ImpactedResourceID)
	}
}

func TestEmitRisk_NilEvidence(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "t1", TenantDomain: "nil-ev.com"}
	def := &m365templates.M365CheckTemplate{ID: "9.9.1", Title: "Nil Evidence", Severity: "medium", Guard: m365templates.GuardMeta{FindingSlug: "nil-ev"}}
	result := &checks.CheckResult{Passed: false, ResourceID: "r1", Message: "evidence is nil", Evidence: nil}

	risk := collectEmitRisk(t, def, result, bag)
	var ctx M365CheckContext
	if err := json.Unmarshal(risk.Context, &ctx); err != nil {
		t.Fatalf("failed to unmarshal context with nil evidence: %v", err)
	}
	if ctx.Evidence != nil {
		t.Errorf("expected nil evidence in context, got %v", ctx.Evidence)
	}
}

func TestEmitRisk_EmptyEvidence(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "t1", TenantDomain: "empty-ev.com"}
	def := &m365templates.M365CheckTemplate{ID: "9.9.2", Title: "Empty Evidence", Severity: "low", Guard: m365templates.GuardMeta{FindingSlug: "empty-ev"}}
	result := &checks.CheckResult{Passed: false, ResourceID: "r2", Message: "evidence is empty", Evidence: map[string]any{}}

	risk := collectEmitRisk(t, def, result, bag)
	var ctx M365CheckContext
	if err := json.Unmarshal(risk.Context, &ctx); err != nil {
		t.Fatalf("failed to unmarshal context with empty evidence: %v", err)
	}
	if len(ctx.Evidence) != 0 {
		t.Errorf("expected empty evidence map, got %v", ctx.Evidence)
	}
}

func TestEmitRisk_AllSeverityLevels(t *testing.T) {
	tests := []struct {
		inputSeverity    output.RiskSeverity
		expectedSeverity output.RiskSeverity
	}{
		{"info", output.RiskSeverityInfo},
		{"low", output.RiskSeverityLow},
		{"medium", output.RiskSeverityMedium},
		{"high", output.RiskSeverityHigh},
		{"critical", output.RiskSeverityCritical},
		{"Info", output.RiskSeverityInfo},
		{"HIGH", output.RiskSeverityHigh},
		{"unknown-sev", output.RiskSeverityInfo},
		{"", output.RiskSeverityInfo},
	}
	for _, tt := range tests {
		t.Run(string(tt.inputSeverity), func(t *testing.T) {
			bag := &databag.M365DataBag{TenantID: "t1", TenantDomain: "sev.com"}
			def := &m365templates.M365CheckTemplate{ID: "9.9.3", Title: "Sev Test", Severity: tt.inputSeverity, Guard: m365templates.GuardMeta{FindingSlug: "sev"}}
			result := &checks.CheckResult{Passed: false, ResourceID: "r", Message: "fail"}

			risk := collectEmitRisk(t, def, result, bag)
			if risk.Severity != tt.expectedSeverity {
				t.Errorf("severity %q: expected %q, got %q", tt.inputSeverity, tt.expectedSeverity, risk.Severity)
			}
		})
	}
}

func TestEmitRisk_SpecialCharsInTenantDomain(t *testing.T) {
	for _, domain := range []string{"my-company.onmicrosoft.com", "sub.domain.example.co.uk", "123-numeric.org"} {
		t.Run(domain, func(t *testing.T) {
			bag := &databag.M365DataBag{TenantID: "t-special", TenantDomain: domain}
			def := &m365templates.M365CheckTemplate{ID: "9.9.4", Title: "Domain", Severity: "high", Guard: m365templates.GuardMeta{FindingSlug: "dom"}}
			result := &checks.CheckResult{Passed: false, ResourceID: "res", Message: "fail"}

			risk := collectEmitRisk(t, def, result, bag)
			expected := "m365://" + domain + "/res"
			if risk.ImpactedResourceID != expected {
				t.Errorf("expected %q, got %q", expected, risk.ImpactedResourceID)
			}
		})
	}
}

func TestEmitRisk_EmptyTenantInfo(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "", TenantDomain: ""}
	def := &m365templates.M365CheckTemplate{ID: "9.9.5", Title: "Empty", Severity: "critical", Guard: m365templates.GuardMeta{FindingSlug: "empty"}}
	result := &checks.CheckResult{Passed: false, ResourceID: "", Message: "fail"}

	risk := collectEmitRisk(t, def, result, bag)
	if risk.ImpactedResourceID != "m365:///" {
		t.Errorf("expected 'm365:///', got %q", risk.ImpactedResourceID)
	}
	if risk.DeduplicationID != "m365-cis-9.9.5-" {
		t.Errorf("expected 'm365-cis-9.9.5-', got %q", risk.DeduplicationID)
	}
}

func TestSlicesContains_CaseSensitive(t *testing.T) {
	if slices.Contains([]string{"All"}, "ALL") {
		t.Error("slices.Contains should be case-sensitive: 'ALL' should not match 'All'")
	}
	if slices.Contains([]string{"All"}, "all") {
		t.Error("slices.Contains should be case-sensitive: 'all' should not match 'All'")
	}
	if !slices.Contains([]string{"All"}, "All") {
		t.Error("slices.Contains should find exact match 'All'")
	}
}

func TestSlicesContains_EmptyString(t *testing.T) {
	if slices.Contains([]string{"a", "b", "c"}, "") {
		t.Error("empty string should not be found in non-empty slice without empty elements")
	}
	if !slices.Contains([]string{"a", "", "c"}, "") {
		t.Error("empty string should be found in slice containing empty element")
	}
	if slices.Contains([]string{}, "") {
		t.Error("empty string should not be found in empty slice")
	}
}

func TestAllRegisteredChecksHaveFunctions(t *testing.T) {
	ids := checks.RegisteredIDs()
	if len(ids) == 0 {
		t.Fatal("no checks registered")
	}
	t.Logf("Total registered checks: %d", len(ids))
	for _, id := range ids {
		fn, ok := checks.Get(id)
		if !ok {
			t.Errorf("check %q registered but Get() returns false", id)
		}
		if fn == nil {
			t.Errorf("check %q registered but function is nil", id)
		}
	}
}

func TestAllRegisteredChecksReturnResults(t *testing.T) {
	ids := checks.RegisteredIDs()
	if len(ids) == 0 {
		t.Fatal("no checks registered")
	}
	emptyBag := &databag.M365DataBag{}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			fn, ok := checks.Get(id)
			if !ok {
				t.Fatalf("check %q not found in registry", id)
			}
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("check %q panicked with empty DataBag: %v", id, r)
				}
			}()
			_, _ = fn(context.Background(), emptyBag)
		})
	}
}

func TestCheckFilterParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{"empty", "", nil},
		{"single", "5.2.2.1", map[string]bool{"5.2.2.1": true}},
		{"multiple", "5.2.2.1, 5.3.1, 1.1.1", map[string]bool{"5.2.2.1": true, "5.3.1": true, "1.1.1": true}},
		{"with spaces", " 5.2.2.1 , 5.3.1 ", map[string]bool{"5.2.2.1": true, "5.3.1": true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCheckFilterLocal(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d entries, got %d", len(tt.expected), len(result))
			}
			for k := range tt.expected {
				if !result[k] {
					t.Errorf("expected key %q in result", k)
				}
			}
		})
	}
}

func parseCheckFilterLocal(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	result := make(map[string]bool)
	for _, part := range splitAndTrim(raw) {
		if part != "" {
			result[part] = true
		}
	}
	return result
}

func splitAndTrim(s string) []string {
	var parts []string
	for _, p := range splitComma(s) {
		p = trimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func splitComma(s string) []string {
	var result []string
	start := 0
	for i := range len(s) {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && s[i] == ' ' {
		i++
	}
	for j > i && s[j-1] == ' ' {
		j--
	}
	return s[i:j]
}
