//go:build integration

package recon

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

func TestAWSSubdomainTakeover(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/subdomain-takeover")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "subdomain-takeover")
	if !ok {
		t.Fatal("subdomain-takeover module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-2"},
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

	// The module scans ALL public hosted zones. Filter to risks from our test zone.
	zoneID := fixture.Output("zone_id")
	var testRisks []output.AurelianRisk
	for _, r := range risks {
		if strings.Contains(r.ImpactedResourceID, zoneID) {
			testRisks = append(testRisks, r)
		}
	}
	require.NotEmpty(t, testRisks, "expected at least one risk from the test zone %s", zoneID)

	// --- Per-checker detection subtests ---

	t.Run("detects EB CNAME takeover", func(t *testing.T) {
		ebRecord := fixture.Output("eb_cname_record_name")
		var matched *output.AurelianRisk
		for i := range testRisks {
			if testRisks[i].Name == "eb-subdomain-takeover" &&
				strings.Contains(testRisks[i].ImpactedResourceID, ebRecord) {
				matched = &testRisks[i]
				break
			}
		}
		require.NotNilf(t, matched, "expected eb-subdomain-takeover risk for record %s", ebRecord)

		assert.Equal(t, output.RiskSeverityHigh, matched.Severity)

		var ctx map[string]any
		require.NoError(t, json.Unmarshal(matched.Context, &ctx))
		assert.Contains(t, ctx["cname_target"], "elasticbeanstalk.com",
			"context should reference EB CNAME target")
		assert.Equal(t, fixture.Output("eb_cname_prefix"), ctx["eb_prefix"],
			"context should contain the EB prefix")
		assert.Equal(t, "us-east-2", ctx["eb_region"],
			"context should contain the EB region")
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["recommendation"])
		assert.NotEmpty(t, ctx["references"])
	})

	t.Run("detects EIP dangling A record", func(t *testing.T) {
		eipRecord := fixture.Output("eip_a_record_name")
		var matched *output.AurelianRisk
		for i := range testRisks {
			if testRisks[i].Name == "eip-dangling-a-record" &&
				strings.Contains(testRisks[i].ImpactedResourceID, eipRecord) {
				matched = &testRisks[i]
				break
			}
		}
		require.NotNilf(t, matched, "expected eip-dangling-a-record risk for record %s", eipRecord)

		assert.Equal(t, output.RiskSeverityMedium, matched.Severity)

		var ctx map[string]any
		require.NoError(t, json.Unmarshal(matched.Context, &ctx))
		assert.Equal(t, fixture.Output("dangling_ip"), ctx["dangling_ip"],
			"context should contain the dangling IP")
		assert.NotEmpty(t, ctx["aws_region"], "context should contain the AWS region")
		assert.NotEmpty(t, ctx["aws_service"], "context should contain the AWS service")
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["recommendation"])
		assert.NotEmpty(t, ctx["references"])
	})

	t.Run("detects NS delegation takeover", func(t *testing.T) {
		nsRecord := fixture.Output("ns_record_name")
		var matched *output.AurelianRisk
		for i := range testRisks {
			if testRisks[i].Name == "ns-delegation-takeover" &&
				strings.Contains(testRisks[i].ImpactedResourceID, nsRecord) {
				matched = &testRisks[i]
				break
			}
		}
		require.NotNilf(t, matched, "expected ns-delegation-takeover risk for record %s", nsRecord)

		assert.Equal(t, output.RiskSeverityHigh, matched.Severity)

		var ctx map[string]any
		require.NoError(t, json.Unmarshal(matched.Context, &ctx))
		assert.NotEmpty(t, ctx["nameservers"], "context should list dangling nameservers")
		assert.NotEmpty(t, ctx["query_error"], "context should contain the DNS error type")
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["recommendation"])
		assert.NotEmpty(t, ctx["references"])

		// Verify query_error is one of the expected DNS error classifications.
		validErrors := map[string]bool{
			"NXDOMAIN": true,
			"SERVFAIL": true,
			"REFUSED":  true,
		}
		assert.True(t, validErrors[ctx["query_error"].(string)],
			"query_error should be NXDOMAIN, SERVFAIL, or REFUSED, got %q", ctx["query_error"])
	})

	// --- Negative testing ---

	t.Run("safe CNAME does not trigger finding", func(t *testing.T) {
		safeCname := fixture.Output("safe_cname_record_name")
		for _, r := range testRisks {
			assert.False(t, strings.Contains(r.ImpactedResourceID, safeCname),
				"safe CNAME %s should not trigger a finding (got %s)", safeCname, r.Name)
		}
	})

	t.Run("safe A record does not trigger finding", func(t *testing.T) {
		safeA := fixture.Output("safe_a_record_name")
		for _, r := range testRisks {
			assert.False(t, strings.Contains(r.ImpactedResourceID, safeA),
				"safe A record %s should not trigger a finding (got %s)", safeA, r.Name)
		}
	})

	// --- Cross-cutting field validation ---

	t.Run("all risks have valid risk names", func(t *testing.T) {
		validNames := map[string]bool{
			"eb-subdomain-takeover":  true,
			"eip-dangling-a-record":  true,
			"ns-delegation-takeover": true,
		}
		for _, r := range testRisks {
			assert.True(t, validNames[r.Name],
				"unexpected risk name %q", r.Name)
		}
	})

	t.Run("all risks have expected severity levels", func(t *testing.T) {
		expectedSeverity := map[string]output.RiskSeverity{
			"eb-subdomain-takeover":  output.RiskSeverityHigh,
			"eip-dangling-a-record":  output.RiskSeverityMedium,
			"ns-delegation-takeover": output.RiskSeverityHigh,
		}
		for _, r := range testRisks {
			if expected, ok := expectedSeverity[r.Name]; ok {
				assert.Equal(t, expected, r.Severity,
					"severity mismatch for %s", r.Name)
			}
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

	t.Run("ImpactedResourceIDs follow Route53 ARN format", func(t *testing.T) {
		for _, r := range testRisks {
			assert.True(t, strings.HasPrefix(r.ImpactedResourceID, "arn:aws:route53:::hostedzone/"),
				"ImpactedResourceID %q should start with arn:aws:route53:::hostedzone/", r.ImpactedResourceID)
			assert.Contains(t, r.ImpactedResourceID, zoneID,
				"ImpactedResourceID should contain zone ID %s", zoneID)
			assert.Contains(t, r.ImpactedResourceID, "/recordset/",
				"ImpactedResourceID should contain /recordset/")
		}
	})

	t.Run("all risk contexts contain common Route53 fields", func(t *testing.T) {
		for _, r := range testRisks {
			var ctx map[string]any
			require.NoError(t, json.Unmarshal(r.Context, &ctx))
			assert.NotEmpty(t, ctx["account_id"], "context missing account_id for %s", r.Name)
			assert.Equal(t, zoneID, ctx["zone_id"], "context zone_id mismatch for %s", r.Name)
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
