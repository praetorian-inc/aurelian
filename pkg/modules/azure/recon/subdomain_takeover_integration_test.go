//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/test/testutil"
)

func TestAzureSubdomainTakeover_Integration(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/subdomain-takeover")
	fixture.Setup()

	subscriptionID := fixture.Output("subscription_id")
	zoneName := fixture.Output("zone_name")

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "subdomain-takeover")
	if !ok {
		t.Fatal("module not registered")
	}

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"subscription-ids": []string{subscriptionID},
			"concurrency":      5,
		},
		Context: context.Background(),
	})
	require.NoError(t, err)

	// Filter to only our test zone
	var risks []output.AurelianRisk
	for _, r := range results {
		risk, ok := r.(output.AurelianRisk)
		if !ok {
			continue
		}
		var ctx map[string]any
		json.Unmarshal(risk.Context, &ctx)
		if zn, _ := ctx["zone_name"].(string); zn == zoneName {
			risks = append(risks, risk)
		}
	}

	// Exact count guards against duplicates and false positives
	assert.Len(t, risks, 6, "expected exactly 6 findings (4 CNAME + 1 A + 1 NS)")

	// --- Positive detection subtests with field-level assertions ---

	t.Run("detects dangling App Service CNAME", func(t *testing.T) {
		found := findRisk(risks, "appsvc-subdomain-takeover", fixture.Output("appsvc_cname_record"))
		require.NotNil(t, found, "expected App Service takeover finding")

		assert.Equal(t, output.RiskSeverityHigh, found.Severity)
		assert.Contains(t, found.ImpactedResourceID, "/CNAME/")
		assert.Contains(t, found.ImpactedResourceID, fixture.Output("appsvc_cname_record"))

		ctx := riskContext(t, found)
		assert.Equal(t, "App Service", ctx["service"])
		assert.Equal(t, "CNAME", ctx["record_type"])
		assert.Contains(t, ctx["cname_target"], ".azurewebsites.net")
		assert.NotEmpty(t, ctx["app_name"])
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	t.Run("detects dangling Storage CNAME", func(t *testing.T) {
		found := findRisk(risks, "storage-subdomain-takeover", fixture.Output("storage_cname_record"))
		require.NotNil(t, found, "expected Blob Storage takeover finding")

		assert.Equal(t, output.RiskSeverityCritical, found.Severity)
		assert.Contains(t, found.ImpactedResourceID, "/CNAME/")
		assert.Contains(t, found.ImpactedResourceID, fixture.Output("storage_cname_record"))

		ctx := riskContext(t, found)
		assert.Equal(t, "Blob Storage", ctx["service"])
		assert.Equal(t, "CNAME", ctx["record_type"])
		assert.Contains(t, ctx["cname_target"], ".blob.core.windows.net")
		assert.NotEmpty(t, ctx["account_name"])
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	t.Run("detects dangling Traffic Manager CNAME", func(t *testing.T) {
		found := findRisk(risks, "trafficmgr-subdomain-takeover", fixture.Output("trafficmgr_cname_record"))
		require.NotNil(t, found, "expected Traffic Manager takeover finding")

		assert.Equal(t, output.RiskSeverityHigh, found.Severity)
		assert.Contains(t, found.ImpactedResourceID, "/CNAME/")
		assert.Contains(t, found.ImpactedResourceID, fixture.Output("trafficmgr_cname_record"))

		ctx := riskContext(t, found)
		assert.Equal(t, "Traffic Manager", ctx["service"])
		assert.Equal(t, "CNAME", ctx["record_type"])
		assert.Contains(t, ctx["cname_target"], ".trafficmanager.net")
		assert.NotEmpty(t, ctx["profile_name"])
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	t.Run("detects dangling CDN CNAME", func(t *testing.T) {
		found := findRisk(risks, "cdn-subdomain-takeover", fixture.Output("cdn_cname_record"))
		require.NotNil(t, found, "expected CDN takeover finding")

		assert.Equal(t, output.RiskSeverityHigh, found.Severity)
		assert.Contains(t, found.ImpactedResourceID, "/CNAME/")
		assert.Contains(t, found.ImpactedResourceID, fixture.Output("cdn_cname_record"))

		ctx := riskContext(t, found)
		assert.Equal(t, "CDN (Classic)", ctx["service"])
		assert.Equal(t, "CNAME", ctx["record_type"])
		assert.Contains(t, ctx["cname_target"], ".azureedge.net")
		assert.NotEmpty(t, ctx["endpoint_name"])
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	t.Run("detects orphaned IP A record", func(t *testing.T) {
		found := findRisk(risks, "orphaned-ip-a-record", fixture.Output("orphaned_ip_record"))
		require.NotNil(t, found, "expected orphaned IP finding")

		assert.Equal(t, output.RiskSeverityLow, found.Severity)
		assert.Contains(t, found.ImpactedResourceID, "/A/")
		assert.Contains(t, found.ImpactedResourceID, fixture.Output("orphaned_ip_record"))

		ctx := riskContext(t, found)
		assert.Equal(t, "Public IP Address", ctx["service"])
		assert.Equal(t, "A", ctx["record_type"])
		assert.Equal(t, fixture.Output("orphaned_ip"), ctx["dangling_ip"])
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	t.Run("detects dangling NS delegation", func(t *testing.T) {
		found := findRisk(risks, "ns-delegation-takeover", fixture.Output("ns_record"))
		require.NotNil(t, found, "expected NS delegation takeover finding")

		assert.Equal(t, output.RiskSeverityCritical, found.Severity)
		assert.Contains(t, found.ImpactedResourceID, "/NS/")
		assert.Contains(t, found.ImpactedResourceID, fixture.Output("ns_record"))

		ctx := riskContext(t, found)
		assert.Equal(t, "Azure DNS", ctx["service"])
		assert.Equal(t, "NS", ctx["record_type"])
		assert.NotEmpty(t, ctx["nameservers"])
		assert.NotEmpty(t, ctx["query_error"])
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	// --- Negative tests: safe records must not produce findings ---

	t.Run("safe CNAME does not trigger finding", func(t *testing.T) {
		found := findRisk(risks, "", fixture.Output("safe_cname_record"))
		assert.Nil(t, found, "safe CNAME pointing to www.example.com should not trigger")
	})

	t.Run("safe A record does not trigger finding", func(t *testing.T) {
		found := findRisk(risks, "", fixture.Output("safe_a_record"))
		assert.Nil(t, found, "safe A record with private IP should not trigger")
	})

	// --- Structural integrity subtests ---

	t.Run("all risks have valid risk names", func(t *testing.T) {
		validNames := map[string]bool{
			"appsvc-subdomain-takeover":      true,
			"storage-subdomain-takeover":     true,
			"trafficmgr-subdomain-takeover":  true,
			"cdn-subdomain-takeover":         true,
			"orphaned-ip-a-record":           true,
			"ns-delegation-takeover":         true,
		}
		for _, r := range risks {
			assert.True(t, validNames[r.Name], "unexpected risk name: %s", r.Name)
		}
	})

	t.Run("all risks have non-empty context", func(t *testing.T) {
		for _, r := range risks {
			assert.NotEmpty(t, r.Context, "risk %s has empty context", r.Name)
		}
	})

	t.Run("all risks have non-empty DeduplicationID", func(t *testing.T) {
		for _, r := range risks {
			assert.NotEmpty(t, r.DeduplicationID, "risk %s has empty DeduplicationID", r.Name)
		}
	})

	t.Run("ImpactedResourceIDs follow Azure resource path format", func(t *testing.T) {
		for _, r := range risks {
			assert.True(t, strings.HasPrefix(r.ImpactedResourceID, "/subscriptions/"),
				"risk %s has invalid resource ID: %s", r.Name, r.ImpactedResourceID)
			assert.Contains(t, r.ImpactedResourceID, "Microsoft.Network/dnsZones",
				"risk %s resource ID missing DNS zone provider: %s", r.Name, r.ImpactedResourceID)
		}
	})

	t.Run("all risk contexts contain common DNS fields", func(t *testing.T) {
		requiredFields := []string{"subscription_id", "zone_name", "record_name", "record_type", "record_values", "fqdn", "resource_group"}
		for _, r := range risks {
			ctx := riskContext(t, &r)
			for _, field := range requiredFields {
				assert.Contains(t, ctx, field, "risk %s missing context field %q", r.Name, field)
			}
		}
	})

	t.Run("all risk contexts include remediation guidance", func(t *testing.T) {
		for _, r := range risks {
			ctx := riskContext(t, &r)
			assert.NotEmpty(t, ctx["description"], "risk %s has empty description", r.Name)
			assert.NotEmpty(t, ctx["remediation"], "risk %s has empty remediation", r.Name)
			refs, _ := ctx["references"].([]any)
			assert.NotEmpty(t, refs, "risk %s has no references", r.Name)
		}
	})

	t.Run("DeduplicationIDs are unique", func(t *testing.T) {
		seen := make(map[string]bool)
		for _, r := range risks {
			assert.False(t, seen[r.DeduplicationID], "duplicate DeduplicationID: %s", r.DeduplicationID)
			seen[r.DeduplicationID] = true
		}
	})

	t.Run("severities are valid RiskSeverity values", func(t *testing.T) {
		validSeverities := map[output.RiskSeverity]bool{
			output.RiskSeverityLow:      true,
			output.RiskSeverityMedium:   true,
			output.RiskSeverityHigh:     true,
			output.RiskSeverityCritical: true,
		}
		for _, r := range risks {
			assert.True(t, validSeverities[r.Severity], "risk %s has invalid severity: %s", r.Name, r.Severity)
		}
	})
}

func findRisk(risks []output.AurelianRisk, name, recordName string) *output.AurelianRisk {
	for _, r := range risks {
		var ctx map[string]any
		json.Unmarshal(r.Context, &ctx)
		rn, _ := ctx["record_name"].(string)

		if name != "" && r.Name != name {
			continue
		}
		if rn == recordName {
			return &r
		}
	}
	return nil
}

func riskContext(t *testing.T, r *output.AurelianRisk) map[string]any {
	t.Helper()
	var ctx map[string]any
	require.NoError(t, json.Unmarshal(r.Context, &ctx), "failed to unmarshal context for risk %s", r.Name)
	return ctx
}
