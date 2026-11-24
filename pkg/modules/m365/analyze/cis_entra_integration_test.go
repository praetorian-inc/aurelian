//go:build integration

package analyze

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCISEntraIntegration(t *testing.T) {
	// This test requires valid Azure/M365 credentials
	mod, ok := plugin.Get(plugin.PlatformM365, plugin.CategoryAnalyze, "cis-entra")
	if !ok {
		t.Fatal("cis-entra module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)

	// Should produce at least some results (findings)
	t.Logf("cis-entra produced %d findings", len(results))

	// Invariant: no duplicate deduplication IDs
	seen := make(map[string]bool)

	validSeverities := map[output.RiskSeverity]bool{
		output.RiskSeverityInfo:     true,
		output.RiskSeverityLow:      true,
		output.RiskSeverityMedium:   true,
		output.RiskSeverityHigh:     true,
		output.RiskSeverityCritical: true,
	}

	// Verify result structure with per-check-ID subtests
	for _, r := range results {
		risk, ok := r.(output.AurelianRisk)
		if !ok {
			t.Errorf("expected AurelianRisk, got %T", r)
			continue
		}

		// Invariant: no duplicates
		require.False(t, seen[risk.DeduplicationID], "duplicate deduplication ID: %s", risk.DeduplicationID)
		seen[risk.DeduplicationID] = true

		// Unmarshal context to validate JSON structure
		var ctx M365CheckContext
		require.NoError(t, json.Unmarshal(risk.Context, &ctx), "Context should be valid M365CheckContext JSON for %s", risk.Name)

		// Per-check subtest keyed by CIS ID for granular failure reporting
		t.Run("CIS-"+ctx.CISID, func(t *testing.T) {
			// Risk field assertions
			assert.NotEmpty(t, risk.Name, "risk name should be populated")
			assert.NotEmpty(t, risk.Severity, "severity should be populated")
			assert.True(t, validSeverities[risk.Severity], "severity %q should be valid", risk.Severity)
			assert.NotEmpty(t, risk.ImpactedResourceID, "impacted resource ID should be populated")
			assert.Contains(t, risk.ImpactedResourceID, "m365://", "resource ID should have m365:// prefix")
			assert.NotEmpty(t, risk.DeduplicationID, "deduplication ID should be populated")
			assert.Contains(t, risk.DeduplicationID, "m365-cis-", "dedup ID should have m365-cis- prefix")

			// Context JSON field assertions
			assert.NotEmpty(t, ctx.CISID, "context.cis_id should be populated")
			assert.NotEmpty(t, ctx.CISTitle, "context.cis_title should be populated")
			assert.NotEmpty(t, ctx.Service, "context.service should be populated")
			assert.NotEmpty(t, ctx.Message, "context.message should be populated")
			assert.NotEmpty(t, ctx.TenantID, "context.tenant_id should be populated")
			assert.NotEmpty(t, ctx.TenantDomain, "context.tenant_domain should be populated")
			assert.NotEmpty(t, ctx.Guard.FindingSlug, "context.guard.finding_slug should be populated")
			assert.NotEmpty(t, ctx.Guard.PhaseTag, "context.guard.phase_tag should be populated")
			assert.Contains(t, ctx.Guard.PhaseTag, "phase_m365_", "phase_tag should have phase_m365_ prefix")
		})
	}
}

func TestCISAllIntegration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformM365, plugin.CategoryAnalyze, "cis-all")
	if !ok {
		t.Fatal("cis-all module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)

	t.Logf("cis-all produced %d findings", len(results))

	// Invariant: no duplicate deduplication IDs
	seenAll := make(map[string]bool)
	for _, r := range results {
		risk, ok := r.(output.AurelianRisk)
		if !ok {
			continue
		}
		require.False(t, seenAll[risk.DeduplicationID], "duplicate deduplication ID: %s", risk.DeduplicationID)
		seenAll[risk.DeduplicationID] = true

		// Invariant: all results should have required fields
		assert.NotEmpty(t, risk.Name, "risk name should be populated")
		assert.NotEmpty(t, risk.Severity, "severity should be populated")
		assert.NotEmpty(t, risk.Context, "context should be populated")

		// Invariant: context should be valid JSON with core fields
		var ctx M365CheckContext
		if assert.NoError(t, json.Unmarshal(risk.Context, &ctx), "context should be valid JSON") {
			assert.NotEmpty(t, ctx.CISID, "context.cis_id should be populated")
			assert.NotEmpty(t, ctx.Service, "context.service should be populated")
		}
	}
}

func TestCISEntraWithCheckFilter(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformM365, plugin.CategoryAnalyze, "cis-entra")
	if !ok {
		t.Fatal("cis-entra module not registered in plugin system")
	}

	// Only run specific checks
	cfg := plugin.Config{
		Args: map[string]any{
			"checks": "5.2.2.1,5.3.1",
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)

	// Should have at most 2 findings (one per filtered check)
	t.Logf("filtered cis-entra produced %d findings", len(results))
	assert.LessOrEqual(t, len(results), 2, "filtered run should produce at most 2 findings")
}

func TestCISEntraWithExcludeFilter(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformM365, plugin.CategoryAnalyze, "cis-entra")
	if !ok {
		t.Fatal("cis-entra module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"exclude-checks": "5.2.2.1,5.3.1",
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)

	t.Logf("cis-entra with exclusions produced %d findings", len(results))

	for _, r := range results {
		risk, ok := r.(output.AurelianRisk)
		if !ok {
			continue
		}
		assert.NotContains(t, risk.DeduplicationID, "m365-cis-5.2.2.1-", "excluded check 5.2.2.1 should not appear")
		assert.NotContains(t, risk.DeduplicationID, "m365-cis-5.3.1-", "excluded check 5.3.1 should not appear")
	}
}

func TestCISEntraEmptyResult(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformM365, plugin.CategoryAnalyze, "cis-entra")
	if !ok {
		t.Fatal("cis-entra module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"checks": "99.99.99", // non-existent CIS ID
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err, "module should not error when no checks match")
	assert.Empty(t, results, "non-existent check filter should produce zero findings")
}

func TestModuleRegistration(t *testing.T) {
	modules := []struct {
		platform plugin.Platform
		category plugin.Category
		id       string
	}{
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-entra"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-defender"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-exchange"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-sharepoint"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-teams"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-admin"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-all"},
	}

	for _, m := range modules {
		t.Run(m.id, func(t *testing.T) {
			mod, ok := plugin.Get(m.platform, m.category, m.id)
			require.True(t, ok, "module %s not registered", m.id)
			assert.Equal(t, m.id, mod.ID())
			assert.Equal(t, m.platform, mod.Platform())
			assert.Equal(t, m.category, mod.Category())
			assert.NotEmpty(t, mod.Description())
			assert.NotEmpty(t, mod.Authors())
			assert.NotNil(t, mod.Parameters())
		})
	}
}

func TestModuleParameterValidation(t *testing.T) {
	modules := []struct {
		platform plugin.Platform
		category plugin.Category
		id       string
	}{
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-entra"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-defender"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-exchange"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-sharepoint"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-teams"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-admin"},
		{plugin.PlatformM365, plugin.CategoryAnalyze, "cis-all"},
	}

	for _, m := range modules {
		t.Run(m.id, func(t *testing.T) {
			mod, ok := plugin.Get(m.platform, m.category, m.id)
			require.True(t, ok, "module %s should be registered", m.id)

			params := mod.Parameters()
			require.NotNil(t, params, "Parameters() should not return nil for %s", m.id)

			v := reflect.ValueOf(params)
			assert.Equal(t, reflect.Ptr, v.Kind(), "Parameters() should return a pointer for %s", m.id)
			assert.Equal(t, reflect.Struct, v.Elem().Kind(), "Parameters() should point to a struct for %s", m.id)
			assert.Greater(t, v.Elem().NumField(), 0, "parameter struct should have fields for %s", m.id)
		})
	}
}

func TestCheckRegistryNoDuplicates(t *testing.T) {
	ids := checks.RegisteredIDs()
	require.NotEmpty(t, ids, "check registry should have entries")

	seen := make(map[string]bool)
	for _, id := range ids {
		if seen[id] {
			t.Errorf("duplicate CIS ID in registry: %s", id)
		}
		seen[id] = true
	}

	t.Logf("verified %d unique CIS IDs in registry", len(seen))
}
