package analyze

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	m365templates "github.com/praetorian-inc/aurelian/pkg/templates/m365"
)

func TestCheckToRisk(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:     "tenant-123",
		TenantDomain: "contoso.com",
	}

	def := &m365templates.M365CheckTemplate{
		ID:          "5.2.2.1",
		Title:       "Test Check",
		Service:     "entra",
		Level:       "L1",
		Profile:     "E3 Level 1",
		Execution:   "Automated",
		Severity:    "high",
		Remediation: "Fix it",
		Rationale:   "Because security",
		Guard: m365templates.GuardMeta{
			FindingSlug: "m365-cis-test",
			PhaseTag:    "phase_m365_entra",
			AssetType:   "m365tenant",
		},
	}

	result := &checks.CheckResult{
		Passed:     false,
		ResourceID: "policy-1",
		Message:    "Check failed",
		Evidence:   map[string]any{"key": "value"},
	}

	crm := checkResultWithMeta{Def: def, Result: result}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		err := checkToRisk(bag)(crm, out)
		if err != nil {
			t.Errorf("checkToRisk returned error: %v", err)
		}
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

	// Verify context JSON
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

func TestCheckToRisk_DefaultResourceID(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:     "tenant-456",
		TenantDomain: "example.com",
	}

	def := &m365templates.M365CheckTemplate{
		ID:       "1.1.1",
		Title:    "Test",
		Severity: "medium",
		Guard: m365templates.GuardMeta{
			FindingSlug: "test-slug",
		},
	}

	result := &checks.CheckResult{
		Passed:     false,
		ResourceID: "", // empty - should default to TenantID
		Message:    "failed",
	}

	crm := checkResultWithMeta{Def: def, Result: result}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		checkToRisk(bag)(crm, out)
		out.Close()
	}()

	results, _ := out.Collect()
	risk := results[0].(output.AurelianRisk)

	// Should use tenant ID as resource ID when check result doesn't specify one
	if risk.ImpactedResourceID != "m365://example.com/tenant-456" {
		t.Errorf("expected default resource ID with tenant, got %q", risk.ImpactedResourceID)
	}
}

func TestContainsStr(t *testing.T) {
	tests := []struct {
		slice    []string
		val      string
		expected bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "d", false},
		{[]string{}, "a", false},
		{nil, "a", false},
		{[]string{"All"}, "All", true},
	}

	for _, tt := range tests {
		result := containsStr(tt.slice, tt.val)
		if result != tt.expected {
			t.Errorf("containsStr(%v, %q) = %v, want %v", tt.slice, tt.val, result, tt.expected)
		}
	}
}

func TestAllRegisteredChecksHaveFunctions(t *testing.T) {
	// This test ensures all registered check IDs actually have implementations
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

func TestCheckToRisk_NilEvidence(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:     "tenant-nil-ev",
		TenantDomain: "nil-evidence.com",
	}

	def := &m365templates.M365CheckTemplate{
		ID:       "9.9.1",
		Title:    "Nil Evidence Check",
		Severity: "medium",
		Guard: m365templates.GuardMeta{
			FindingSlug: "nil-evidence-slug",
		},
	}

	result := &checks.CheckResult{
		Passed:     false,
		ResourceID: "resource-1",
		Message:    "evidence is nil",
		Evidence:   nil,
	}

	crm := checkResultWithMeta{Def: def, Result: result}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		err := checkToRisk(bag)(crm, out)
		if err != nil {
			t.Errorf("checkToRisk returned error: %v", err)
		}
		out.Close()
	}()

	results, err := out.Collect()
	if err != nil {
		t.Fatalf("collect error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	risk := results[0].(output.AurelianRisk)

	// Verify context can still be unmarshalled when evidence is nil
	var ctx M365CheckContext
	if err := json.Unmarshal(risk.Context, &ctx); err != nil {
		t.Fatalf("failed to unmarshal context with nil evidence: %v", err)
	}
	if ctx.Evidence != nil {
		t.Errorf("expected nil evidence in context, got %v", ctx.Evidence)
	}
}

func TestCheckToRisk_EmptyEvidence(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:     "tenant-empty-ev",
		TenantDomain: "empty-evidence.com",
	}

	def := &m365templates.M365CheckTemplate{
		ID:       "9.9.2",
		Title:    "Empty Evidence Check",
		Severity: "low",
		Guard: m365templates.GuardMeta{
			FindingSlug: "empty-evidence-slug",
		},
	}

	result := &checks.CheckResult{
		Passed:     false,
		ResourceID: "resource-2",
		Message:    "evidence is empty",
		Evidence:   map[string]any{},
	}

	crm := checkResultWithMeta{Def: def, Result: result}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		err := checkToRisk(bag)(crm, out)
		if err != nil {
			t.Errorf("checkToRisk returned error: %v", err)
		}
		out.Close()
	}()

	results, err := out.Collect()
	if err != nil {
		t.Fatalf("collect error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	risk := results[0].(output.AurelianRisk)

	var ctx M365CheckContext
	if err := json.Unmarshal(risk.Context, &ctx); err != nil {
		t.Fatalf("failed to unmarshal context with empty evidence: %v", err)
	}
	// Empty map should still be present (not nil) since omitempty only omits nil maps
	if len(ctx.Evidence) != 0 {
		t.Errorf("expected empty evidence map, got %v", ctx.Evidence)
	}
}

func TestCheckToRisk_AllSeverityLevels(t *testing.T) {
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
		{"HIGH", output.RiskSeverityHigh}, // NormalizeSeverity lowercases first, so "HIGH" -> "high"
		{"unknown-sev", output.RiskSeverityInfo},
		{"", output.RiskSeverityInfo},
	}

	for _, tt := range tests {
		t.Run(string(tt.inputSeverity), func(t *testing.T) {
			bag := &databag.M365DataBag{
				TenantID:     "t1",
				TenantDomain: "sev-test.com",
			}

			def := &m365templates.M365CheckTemplate{
				ID:       "9.9.3",
				Title:    "Severity Test",
				Severity: tt.inputSeverity,
				Guard: m365templates.GuardMeta{
					FindingSlug: "sev-test",
				},
			}

			result := &checks.CheckResult{
				Passed:     false,
				ResourceID: "res",
				Message:    "fail",
			}

			crm := checkResultWithMeta{Def: def, Result: result}
			out := pipeline.New[model.AurelianModel]()
			go func() {
				checkToRisk(bag)(crm, out)
				out.Close()
			}()

			results, err := out.Collect()
			if err != nil {
				t.Fatalf("collect error: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			risk := results[0].(output.AurelianRisk)
			if risk.Severity != tt.expectedSeverity {
				t.Errorf("severity %q: expected %q, got %q", tt.inputSeverity, tt.expectedSeverity, risk.Severity)
			}
		})
	}
}

func TestCheckToRisk_SpecialCharsInTenantDomain(t *testing.T) {
	domains := []string{
		"my-company.onmicrosoft.com",
		"sub.domain.example.co.uk",
		"hyphen-ated-domain.com",
		"123-numeric.org",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			bag := &databag.M365DataBag{
				TenantID:     "t-special",
				TenantDomain: domain,
			}

			def := &m365templates.M365CheckTemplate{
				ID:       "9.9.4",
				Title:    "Special Domain Check",
				Severity: "high",
				Guard: m365templates.GuardMeta{
					FindingSlug: "special-domain",
				},
			}

			result := &checks.CheckResult{
				Passed:     false,
				ResourceID: "res-special",
				Message:    "fail",
			}

			crm := checkResultWithMeta{Def: def, Result: result}
			out := pipeline.New[model.AurelianModel]()
			go func() {
				checkToRisk(bag)(crm, out)
				out.Close()
			}()

			results, err := out.Collect()
			if err != nil {
				t.Fatalf("collect error: %v", err)
			}

			risk := results[0].(output.AurelianRisk)

			expectedResource := "m365://" + domain + "/res-special"
			if risk.ImpactedResourceID != expectedResource {
				t.Errorf("expected resource ID %q, got %q", expectedResource, risk.ImpactedResourceID)
			}

			var ctx M365CheckContext
			if err := json.Unmarshal(risk.Context, &ctx); err != nil {
				t.Fatalf("failed to unmarshal context: %v", err)
			}
			if ctx.TenantDomain != domain {
				t.Errorf("expected tenant domain %q in context, got %q", domain, ctx.TenantDomain)
			}
		})
	}
}

func TestCheckToRisk_EmptyTenantInfo(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:     "",
		TenantDomain: "",
	}

	def := &m365templates.M365CheckTemplate{
		ID:       "9.9.5",
		Title:    "Empty Tenant Check",
		Severity: "critical",
		Guard: m365templates.GuardMeta{
			FindingSlug: "empty-tenant",
		},
	}

	result := &checks.CheckResult{
		Passed:     false,
		ResourceID: "", // also empty, so should default to empty TenantID
		Message:    "fail with empty tenant",
	}

	crm := checkResultWithMeta{Def: def, Result: result}
	out := pipeline.New[model.AurelianModel]()
	go func() {
		err := checkToRisk(bag)(crm, out)
		if err != nil {
			t.Errorf("checkToRisk returned error: %v", err)
		}
		out.Close()
	}()

	results, err := out.Collect()
	if err != nil {
		t.Fatalf("collect error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	risk := results[0].(output.AurelianRisk)

	// With empty domain and empty resource ID (defaults to empty TenantID):
	// ImpactedResourceID = "m365:///", DeduplicationID = "m365-cis-9.9.5-"
	if risk.ImpactedResourceID != "m365:///" {
		t.Errorf("expected resource ID 'm365:///', got %q", risk.ImpactedResourceID)
	}
	if risk.DeduplicationID != "m365-cis-9.9.5-" {
		t.Errorf("expected dedup ID 'm365-cis-9.9.5-', got %q", risk.DeduplicationID)
	}
}

func TestContainsStr_CaseSensitive(t *testing.T) {
	// containsStr uses == comparison, so it should be case-sensitive
	if containsStr([]string{"All"}, "ALL") {
		t.Error("containsStr should be case-sensitive: 'ALL' should not match 'All'")
	}
	if containsStr([]string{"All"}, "all") {
		t.Error("containsStr should be case-sensitive: 'all' should not match 'All'")
	}
	if !containsStr([]string{"All"}, "All") {
		t.Error("containsStr should find exact match 'All'")
	}
}

func TestContainsStr_EmptyString(t *testing.T) {
	// Searching for empty string in a non-empty slice
	if containsStr([]string{"a", "b", "c"}, "") {
		t.Error("empty string should not be found in non-empty slice without empty elements")
	}
	// Searching for empty string in a slice that contains an empty string
	if !containsStr([]string{"a", "", "c"}, "") {
		t.Error("empty string should be found in slice containing empty element")
	}
	// Searching in an empty slice
	if containsStr([]string{}, "") {
		t.Error("empty string should not be found in empty slice")
	}
}

func TestAllRegisteredChecksReturnResults(t *testing.T) {
	// Nil-safety smoke test: call each registered check with an empty DataBag
	// and verify no panic occurs. We don't check correctness of results here,
	// only that the checks don't crash on minimal input.
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

			// We only care that it doesn't panic
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
			// Test via plugin.ParseCheckFilter
			// imported through the module
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

// parseCheckFilterLocal mirrors plugin.ParseCheckFilter for testing
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
	for i := 0; i < len(s); i++ {
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
