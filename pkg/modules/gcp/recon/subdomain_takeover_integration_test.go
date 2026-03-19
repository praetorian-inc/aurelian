//go:build integration

package recon_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPSubdomainTakeover(t *testing.T) {
	fixture := testutil.NewGCPFixture(t, "gcp/recon/subdomain-takeover")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformGCP, plugin.CategoryRecon, "subdomain-takeover")
	if !ok {
		t.Fatal("gcp subdomain-takeover module not registered in plugin system")
	}

	projectID := fixture.Output("project_id")

	cfg := plugin.Config{
		Args: map[string]any{
			"project-id": []string{projectID},
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var risks []output.AurelianRisk
	for m := range p2.Range() {
		if r, ok := m.(output.AurelianRisk); ok {
			risks = append(risks, r)
		}
	}
	require.NoError(t, p2.Wait())

	// Filter to risks from our test zone (module scans all zones in the project).
	zoneName := fixture.Output("zone_name")
	var testRisks []output.AurelianRisk
	for _, r := range risks {
		if strings.Contains(r.ImpactedResourceID, zoneName) {
			testRisks = append(testRisks, r)
		}
	}
	require.NotEmpty(t, testRisks, "expected at least one risk from test zone %s", zoneName)

	// --- Per-checker detection subtests ---

	t.Run("detects dangling Storage CNAME", func(t *testing.T) {
		recordName := fixture.Output("storage_cname_record")
		matched := findRiskByRecord(testRisks, recordName)
		require.NotNilf(t, matched, "expected risk for dangling storage CNAME %s", recordName)

		assert.Equal(t, output.RiskSeverityCritical, matched.Severity)
		assert.Contains(t, matched.Name, "Cloud Storage")

		var ctx map[string]any
		require.NoError(t, json.Unmarshal(matched.Context, &ctx))
		assert.Equal(t, "Cloud Storage", ctx["service"])
		assert.Contains(t, ctx["target"], "storage.googleapis.com")
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	t.Run("detects dangling Cloud Run CNAME", func(t *testing.T) {
		recordName := fixture.Output("run_cname_record")
		matched := findRiskByRecord(testRisks, recordName)
		require.NotNilf(t, matched, "expected risk for dangling Cloud Run CNAME %s", recordName)

		assert.Equal(t, output.RiskSeverityHigh, matched.Severity)
		assert.Contains(t, matched.Name, "Cloud Run")

		var ctx map[string]any
		require.NoError(t, json.Unmarshal(matched.Context, &ctx))
		assert.Equal(t, "Cloud Run", ctx["service"])
		assert.Contains(t, ctx["target"], ".run.app")
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	t.Run("detects dangling App Engine CNAME", func(t *testing.T) {
		recordName := fixture.Output("appengine_cname_record")
		matched := findRiskByRecord(testRisks, recordName)
		require.NotNilf(t, matched, "expected risk for dangling App Engine CNAME %s", recordName)

		assert.Equal(t, output.RiskSeverityHigh, matched.Severity)
		assert.Contains(t, matched.Name, "App Engine")

		var ctx map[string]any
		require.NoError(t, json.Unmarshal(matched.Context, &ctx))
		assert.Equal(t, "App Engine", ctx["service"])
		assert.Contains(t, ctx["target"], ".appspot.com")
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	t.Run("detects orphaned IP A record", func(t *testing.T) {
		recordName := fixture.Output("orphaned_ip_record")
		matched := findRiskByRecord(testRisks, recordName)
		require.NotNilf(t, matched, "expected risk for orphaned IP record %s", recordName)

		assert.Equal(t, output.RiskSeverityLow, matched.Severity)
		assert.Contains(t, matched.Name, "Orphaned IP")

		var ctx map[string]any
		require.NoError(t, json.Unmarshal(matched.Context, &ctx))
		assert.Equal(t, fixture.Output("orphaned_ip"), ctx["ip"])
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	t.Run("detects dangling NS delegation", func(t *testing.T) {
		recordName := fixture.Output("ns_record")
		matched := findRiskByRecord(testRisks, recordName)
		require.NotNilf(t, matched, "expected risk for dangling NS delegation %s", recordName)

		assert.Equal(t, output.RiskSeverityCritical, matched.Severity)
		assert.Contains(t, matched.Name, "NS Delegation")

		var ctx map[string]any
		require.NoError(t, json.Unmarshal(matched.Context, &ctx))
		assert.Equal(t, "Cloud DNS", ctx["service"])
		assert.Contains(t, ctx["nameserver"], "googledomains.com")
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	// --- Negative testing ---

	t.Run("safe CNAME does not trigger finding", func(t *testing.T) {
		safeCname := fixture.Output("safe_cname_record")
		for _, r := range testRisks {
			assert.False(t, strings.Contains(r.ImpactedResourceID, safeCname),
				"safe CNAME %s should not trigger a finding (got %s)", safeCname, r.Name)
		}
	})

	t.Run("safe A record does not trigger finding", func(t *testing.T) {
		safeA := fixture.Output("safe_a_record")
		for _, r := range testRisks {
			assert.False(t, strings.Contains(r.ImpactedResourceID, safeA),
				"safe A record %s should not trigger a finding (got %s)", safeA, r.Name)
		}
	})

	// --- Cross-cutting field validation ---

	t.Run("all risks have valid risk names", func(t *testing.T) {
		validPrefixes := []string{
			"GCP Subdomain Takeover: Dangling",
			"GCP Subdomain Takeover: Orphaned",
		}
		for _, r := range testRisks {
			hasValid := false
			for _, prefix := range validPrefixes {
				if strings.HasPrefix(r.Name, prefix) {
					hasValid = true
					break
				}
			}
			assert.Truef(t, hasValid, "unexpected risk name %q", r.Name)
		}
	})

	t.Run("all risks have non-empty context", func(t *testing.T) {
		for _, r := range testRisks {
			assert.NotEmpty(t, r.Context,
				"risk context should not be empty for %s (%s)", r.Name, r.ImpactedResourceID)
		}
	})

	t.Run("all risks have non-empty DeduplicationID", func(t *testing.T) {
		for _, r := range testRisks {
			assert.NotEmpty(t, r.DeduplicationID,
				"risk should have DeduplicationID for %s", r.Name)
		}
	})

	t.Run("ImpactedResourceIDs follow GCP resource path format", func(t *testing.T) {
		for _, r := range testRisks {
			assert.True(t, strings.HasPrefix(r.ImpactedResourceID, "projects/"),
				"ImpactedResourceID %q should start with projects/", r.ImpactedResourceID)
			assert.Contains(t, r.ImpactedResourceID, "managedZones/",
				"ImpactedResourceID should contain managedZones/")
			assert.Contains(t, r.ImpactedResourceID, "rrsets/",
				"ImpactedResourceID should contain rrsets/")
		}
	})

	t.Run("all risk contexts contain common DNS fields", func(t *testing.T) {
		for _, r := range testRisks {
			var ctx map[string]any
			require.NoError(t, json.Unmarshal(r.Context, &ctx))
			assert.NotEmpty(t, ctx["project_id"], "context missing project_id for %s", r.Name)
			assert.NotEmpty(t, ctx["zone_name"], "context missing zone_name for %s", r.Name)
			assert.NotEmpty(t, ctx["record_name"], "context missing record_name for %s", r.Name)
			assert.NotEmpty(t, ctx["record_type"], "context missing record_type for %s", r.Name)
			assert.NotNil(t, ctx["record_values"], "context missing record_values for %s", r.Name)
		}
	})

	t.Run("DeduplicationIDs are unique", func(t *testing.T) {
		seen := make(map[string]bool)
		for _, r := range testRisks {
			assert.False(t, seen[r.DeduplicationID],
				"duplicate DeduplicationID %q for %s", r.DeduplicationID, r.Name)
			seen[r.DeduplicationID] = true
		}
	})
}

// findRiskByRecord finds the first risk whose ImpactedResourceID contains the record name.
func findRiskByRecord(risks []output.AurelianRisk, recordName string) *output.AurelianRisk {
	for i := range risks {
		if strings.Contains(risks[i].ImpactedResourceID, recordName) {
			return &risks[i]
		}
	}
	return nil
}
