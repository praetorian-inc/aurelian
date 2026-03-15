//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
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

	t.Run("detects dangling App Service CNAME", func(t *testing.T) {
		found := findRisk(risks, "appsvc-subdomain-takeover", fixture.Output("appsvc_cname_record"))
		if found == nil {
			t.Error("expected App Service takeover finding")
		}
	})

	t.Run("detects dangling Storage CNAME", func(t *testing.T) {
		found := findRisk(risks, "storage-subdomain-takeover", fixture.Output("storage_cname_record"))
		if found == nil {
			t.Error("expected Blob Storage takeover finding")
		}
	})

	t.Run("detects dangling Traffic Manager CNAME", func(t *testing.T) {
		found := findRisk(risks, "trafficmgr-subdomain-takeover", fixture.Output("trafficmgr_cname_record"))
		if found == nil {
			t.Error("expected Traffic Manager takeover finding")
		}
	})

	t.Run("detects dangling CDN CNAME", func(t *testing.T) {
		found := findRisk(risks, "cdn-subdomain-takeover", fixture.Output("cdn_cname_record"))
		if found == nil {
			t.Error("expected CDN takeover finding")
		}
	})

	t.Run("detects orphaned IP A record", func(t *testing.T) {
		found := findRisk(risks, "orphaned-ip-a-record", fixture.Output("orphaned_ip_record"))
		if found == nil {
			t.Error("expected orphaned IP finding")
		}
	})

	t.Run("detects dangling NS delegation", func(t *testing.T) {
		found := findRisk(risks, "ns-delegation-takeover", fixture.Output("ns_record"))
		if found == nil {
			t.Error("expected NS delegation takeover finding")
		}
	})

	t.Run("safe CNAME does not trigger finding", func(t *testing.T) {
		found := findRisk(risks, "", fixture.Output("safe_cname_record"))
		if found != nil {
			t.Errorf("safe CNAME should not trigger, got: %s", found.Name)
		}
	})

	t.Run("safe A record does not trigger finding", func(t *testing.T) {
		found := findRisk(risks, "", fixture.Output("safe_a_record"))
		if found != nil {
			t.Errorf("safe A record should not trigger, got: %s", found.Name)
		}
	})

	t.Run("all risks have valid risk names", func(t *testing.T) {
		for _, r := range risks {
			if r.Name == "" {
				t.Error("risk has empty name")
			}
		}
	})

	t.Run("all risks have non-empty context", func(t *testing.T) {
		for _, r := range risks {
			if len(r.Context) == 0 {
				t.Errorf("risk %s has empty context", r.Name)
			}
		}
	})

	t.Run("all risks have non-empty DeduplicationID", func(t *testing.T) {
		for _, r := range risks {
			if r.DeduplicationID == "" {
				t.Errorf("risk %s has empty DeduplicationID", r.Name)
			}
		}
	})

	t.Run("ImpactedResourceIDs follow Azure resource path format", func(t *testing.T) {
		for _, r := range risks {
			if !strings.HasPrefix(r.ImpactedResourceID, "/subscriptions/") {
				t.Errorf("risk %s has invalid resource ID: %s", r.Name, r.ImpactedResourceID)
			}
		}
	})

	t.Run("all risk contexts contain common DNS fields", func(t *testing.T) {
		requiredFields := []string{"subscription_id", "zone_name", "record_name", "record_type", "record_values"}
		for _, r := range risks {
			var ctx map[string]any
			json.Unmarshal(r.Context, &ctx)
			for _, field := range requiredFields {
				if _, ok := ctx[field]; !ok {
					t.Errorf("risk %s missing context field %q", r.Name, field)
				}
			}
		}
	})

	t.Run("DeduplicationIDs are unique", func(t *testing.T) {
		seen := make(map[string]bool)
		for _, r := range risks {
			if seen[r.DeduplicationID] {
				t.Errorf("duplicate DeduplicationID: %s", r.DeduplicationID)
			}
			seen[r.DeduplicationID] = true
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
