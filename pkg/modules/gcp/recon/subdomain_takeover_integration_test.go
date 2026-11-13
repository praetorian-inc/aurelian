//go:build integration

package recon_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/modules/gcp/recon"
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

	// Registration assertion only. The returned instance is deliberately NOT
	// used to run scans -- see runGCPSubdomainTakeover for why.
	if _, ok := plugin.Get(plugin.PlatformGCP, plugin.CategoryRecon, "subdomain-takeover"); !ok {
		t.Fatal("gcp subdomain-takeover module not registered in plugin system")
	}

	projectID := fixture.Output("project_id")

	risks := runGCPSubdomainTakeover(t, map[string]any{
		"project-id": []string{projectID},
	})

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

	t.Run("direct resource mode detects dangling records", func(t *testing.T) {
		directRisks := runGCPSubdomainTakeover(t, map[string]any{
			"project-id":    []string{projectID},
			"resource-type": []string{"dns.googleapis.com/ManagedZone"},
			"resource-id":   []string{zoneName},
		})
		require.NotEmpty(t, directRisks, "expected direct managed zone scan risks for %s", zoneName)

		for _, recordOutput := range []string{
			"storage_cname_record",
			"run_cname_record",
			"appengine_cname_record",
			"orphaned_ip_record",
			"ns_record",
			// Case 10: delegated name has no zone, only a deeper one does.
			"ns_deep_record",
		} {
			recordName := fixture.Output(recordOutput)
			assert.NotNilf(t, findRiskByRecord(directRisks, recordName), "expected direct scan risk for %s", recordName)
		}

		// Case 8 in direct mode: the delegated child zone lives in the same
		// project that direct mode scopes itself to, so ownership is still
		// established and no risk may be emitted.
		sameProjectChild := fixture.Output("ns_child_same_record")
		assert.Nilf(t, findRiskByRecordType(directRisks, sameProjectChild, "NS"),
			"direct scan reported %s as dangling, but its child zone %s exists in project %s",
			sameProjectChild, fixture.Output("ns_child_same_zone_name"), projectID)

		for _, risk := range directRisks {
			assert.Contains(t, risk.ImpactedResourceID, zoneName)
			assert.NotEmpty(t, risk.Context, "risk context should not be empty for %s", risk.ImpactedResourceID)
		}
	})

	// --- ENG-8964: NS delegation zone-ownership cases (8-12) ---
	//
	// Before this fix the only NS case in this fixture was ns-dangling (case 5),
	// a delegation whose zone exists nowhere -- a true positive. Nothing here
	// exercised a delegation whose zone DOES exist, which is why the
	// false-positive bug reached production. Cases 8-12 close that gap.

	t.Run("case 8: NS delegation to an existing child zone in the same project is not reported", func(t *testing.T) {
		recordName := fixture.Output("ns_child_same_record")
		childZone := fixture.Output("ns_child_same_zone_name")

		matched := findRiskByRecordType(testRisks, recordName, "NS")
		assert.Nilf(t, matched,
			"delegation %s was reported as dangling, but Cloud DNS zone %s in project %s owns that name",
			recordName, childZone, projectID)
	})

	t.Run("case 10: NS delegation is reported when only a deeper zone exists", func(t *testing.T) {
		// A zone BELOW the delegated name (internal.ns-deep.<zone>) is a
		// different zone. It is not evidence that the delegation resolves, so
		// suppressing on it would be a false negative in a takeover detector.
		recordName := fixture.Output("ns_deep_record")
		deeperZone := fixture.Output("ns_deep_existing_zone_dns_name")
		require.Truef(t, strings.HasSuffix(deeperZone, "."+recordName),
			"fixture invariant broken: %q should sit strictly below %q", deeperZone, recordName)

		matched := findRiskByRecordType(testRisks, recordName, "NS")
		require.NotNilf(t, matched,
			"expected a dangling-NS risk for %s; only the deeper zone %s exists, not %s",
			recordName, deeperZone, recordName)

		assert.Equal(t, output.RiskSeverityCritical, matched.Severity)
		assert.Contains(t, matched.Name, "NS Delegation")

		var ctx map[string]any
		require.NoError(t, json.Unmarshal(matched.Context, &ctx))
		assert.Equal(t, "Cloud DNS", ctx["service"])
		assert.Equal(t, recordName, ctx["record_name"])
		assert.Equal(t, "NS", ctx["record_type"])
		assert.Contains(t, ctx["nameserver"], "googledomains.com")
		assert.NotEmpty(t, ctx["description"])
		assert.NotEmpty(t, ctx["remediation"])
	})

	t.Run("case 11: apex NS record set is not reported", func(t *testing.T) {
		// Every Cloud DNS zone carries an apex NS record set automatically. It
		// is the zone's own delegation, not a delegation to a child zone.
		apex := fixture.Output("dns_name")
		matched := findRiskByRecordType(testRisks, apex, "NS")
		assert.Nilf(t, matched, "apex NS record set %s must never be reported as a dangling delegation", apex)
	})

	t.Run("case 11: no apex NS record set in any scanned zone is reported", func(t *testing.T) {
		// Generalization of the case above over every zone the scan touched,
		// including the child zones this fixture creates.
		for _, r := range risks {
			var ctx map[string]any
			require.NoError(t, json.Unmarshal(r.Context, &ctx))
			if ctx["record_type"] != "NS" {
				continue
			}
			recordName, _ := ctx["record_name"].(string)
			zoneDNS, _ := ctx["dns_name"].(string)
			assert.NotEqualf(t, strings.TrimSuffix(zoneDNS, "."), recordName,
				"risk %q is for the apex NS record set of its own zone (%s)", r.Name, zoneDNS)
		}
	})

	t.Run("case 9: cross-project NS delegation", func(t *testing.T) {
		secondaryProjectID := fixture.Output("secondary_project_id")
		requireFixtureReflectsOptIn(t, "TF_VAR_secondary_project_id", secondaryProjectID)
		if secondaryProjectID == "" {
			t.Skip("cross-project NS case not provisioned: set TF_VAR_secondary_project_id " +
				"to a second GCP project in which Cloud DNS zones can be created, then re-run")
		}
		recordName := fixture.Output("ns_child_other_record")
		childZone := fixture.Output("ns_child_other_zone_name")
		require.NotEmpty(t, recordName, "secondary project is configured but ns_child_other_record is empty")

		// The two arms below are the point of this test, and they must BOTH
		// hold. Together they prove the ownership lookup narrows false
		// positives without blanket-suppressing NS findings -- which is exactly
		// what a naive "if the delegation resolves in DNS, suppress it" fix
		// would fail, because an attacker who has already claimed the zone also
		// answers authoritatively.

		t.Run("no risk when the owning project is in scope", func(t *testing.T) {
			bothProjects := runGCPSubdomainTakeover(t, map[string]any{
				"project-id": []string{projectID, secondaryProjectID},
			})
			require.NotEmpty(t, bothProjects, "expected risks from the two-project scan")

			assert.Nilf(t, findRiskByRecordType(bothProjects, recordName, "NS"),
				"delegation %s was reported as dangling, but Cloud DNS zone %s in project %s owns that name",
				recordName, childZone, secondaryProjectID)

			// Widening the scope must not suppress genuinely dangling
			// delegations in the same zone.
			for _, stillDangling := range []string{"ns_record", "ns_deep_record"} {
				name := fixture.Output(stillDangling)
				assert.NotNilf(t, findRiskByRecordType(bothProjects, name, "NS"),
					"%s is genuinely dangling and must still be reported when both projects are in scope", name)
			}
		})

		t.Run("risk when the owning project is out of scope", func(t *testing.T) {
			// testRisks comes from the top-level run, which is scoped to the
			// primary project only. With the owning project out of scope,
			// ownership genuinely cannot be established, so reporting the
			// delegation is correct -- not a regression of the fix.
			matched := findRiskByRecordType(testRisks, recordName, "NS")
			require.NotNilf(t, matched,
				"expected %s to be reported when its owning project %s is outside the scan scope",
				recordName, secondaryProjectID)

			assert.Equal(t, output.RiskSeverityCritical, matched.Severity)
			assert.Contains(t, matched.Name, "NS Delegation")

			var ctx map[string]any
			require.NoError(t, json.Unmarshal(matched.Context, &ctx))
			assert.Equal(t, "Cloud DNS", ctx["service"])
			assert.Equal(t, recordName, ctx["record_name"])
			assert.Equal(t, projectID, ctx["project_id"])
			assert.Contains(t, ctx["nameserver"], "googledomains.com")
			assert.NotEmpty(t, ctx["description"])
			assert.NotEmpty(t, ctx["remediation"])
		})
	})

	t.Run("case 12: NS delegation to a zone past the first list page is not reported", func(t *testing.T) {
		// Pagination-specific fixture resources are opt-in; when they are not
		// provisioned the splat-based outputs are empty.
		fillerCount := strings.TrimSpace(fixture.Output("filler_zone_count"))
		requireFixtureReflectsOptIn(t, "TF_VAR_filler_zone_count", fillerCount)
		recordName := fixture.Output("paged_ns_record")
		if recordName == "" && (fillerCount == "" || fillerCount == "0") {
			t.Skipf("pagination case not provisioned (filler_zone_count=%s): set "+
				"TF_VAR_filler_zone_count to at least 101 and re-run. That provisions "+
				"that many extra Cloud DNS managed zones plus the delegated target "+
				"(~$13.00/month at list price at the minimum of 101, rising linearly), and "+
				"Aurelian fixtures persist until AURELIAN_DESTROY_FIXTURES=1 -- which is "+
				"also what forces the re-apply after you change the variable, because the "+
				"fixture hash covers file contents only, not TF_VAR_* values.",
				fillerCount)
		}
		// Reaching here with an empty record and a non-zero count is neither
		// "not provisioned" nor staleness: the case-12 resources are gated on
		// `count = var.filler_zone_count > 0 ? 1 : 0` (main.tf), so a non-zero
		// count obliges the delegation record to exist. Both messages above
		// would misdiagnose it.
		if recordName == "" {
			t.Fatalf("incomplete fixture: the applied fixture reports %s filler zones, but "+
				"output paged_ns_record is empty. The case-12 resources are gated on "+
				"`count = var.filler_zone_count > 0 ? 1 : 0`, so that delegation record must "+
				"exist whenever the count is non-zero -- the pagination resources were only "+
				"partially applied. Re-run with AURELIAN_DESTROY_FIXTURES=1 to force a "+
				"teardown and redeploy, and first check the project's Cloud DNS managed-zone "+
				"quota: exhausting it part-way through creating %s zones is the most likely "+
				"cause of a partial apply at this scale.", fillerCount, fillerCount)
		}
		targetZone := fixture.Output("paged_target_zone_name")

		// Control. Without one, "no risk for the paged delegation" is
		// indistinguishable from "the module never reached the NS path at all".
		// Case 5 (ns_record) is a genuinely dangling delegation in this same
		// zone, produced by this same module run, so it serves as the control
		// here and no extra fixture resource is needed for it.
		dangling := fixture.Output("ns_record")
		require.NotNilf(t, findRiskByRecordType(testRisks, dangling, "NS"),
			"control failed: %s is genuinely dangling and must still be reported; "+
				"with the NS path silent the pagination assertion below would be vacuous",
			dangling)

		// The asserted invariant is "no risk is emitted for the delegated name",
		// not "the zone was found on page N" -- managedZones.list ordering is
		// not contractually specified. See the ordering note next to case 12 in
		// the fixture's main.tf.
		assert.Nilf(t, findRiskByRecordType(testRisks, recordName, "NS"),
			"delegation %s was reported as dangling, but Cloud DNS zone %s exists in project %s "+
				"(this fixture puts at least %s zones there, so the zone listing spans several pages)",
			recordName, targetZone, projectID, fixture.Output("managed_zone_count"))
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

// requireFixtureReflectsOptIn fails the test when an opt-in TF_VAR_* is set in
// the environment but the applied fixture does not reflect it.
//
// TF_VAR_* values are not part of the fixture hash: computeFixtureHash
// (test/testutil/fixture/hash.go) hashes file paths and contents only, and
// computeEffectiveHash adds only the container (project) ID. So against a
// fixture that has already been applied, exporting a TF_VAR_* leaves both
// hashes unchanged, the harness reuses the existing stack without applying,
// and the resources gated on that variable are never created. The gating
// output then still reads as its default, and skipping there would print a
// message instructing the operator to set a variable they have already set --
// while a green run would read as "this case was covered" when the subtest
// never executed. Fail loudly instead, and name the remedy.
//
// The comparison has two paths, because the two opt-ins have different
// value semantics on the Terraform side. filler_zone_count is a `number`
// variable surfaced as `tostring(var.filler_zone_count)`, and Terraform
// normalizes the number before stringifying it, so TF_VAR_filler_zone_count
// of 150.0, 0150 or 1.5e2 all reach the output as "150". A plain string
// compare would call that a stale fixture and print a remedy
// (AURELIAN_DESTROY_FIXTURES=1) that tears down and recreates ~150 Cloud DNS
// zones which were already correct -- real money and minutes spent on a
// false alarm. So when BOTH sides parse as numbers, compare numerically.
// Otherwise fall back to the trimmed string compare, which keeps exact
// semantics for the values that genuinely are strings:
// secondary_project_id is `var.secondary_project_id`, a GCP project ID that
// never parses as a number and must never be matched loosely.
//
// An unset or empty env var means "not requested" and returns without
// comment, leaving the caller's own t.Skip as the honest path.
func requireFixtureReflectsOptIn(t *testing.T, envVar, got string) {
	t.Helper()

	want := strings.TrimSpace(os.Getenv(envVar))
	if want == "" {
		return
	}
	got = strings.TrimSpace(got)
	if got == want {
		return
	}
	wantNum, wantErr := strconv.ParseFloat(want, 64)
	gotNum, gotErr := strconv.ParseFloat(got, 64)
	if wantErr == nil && gotErr == nil && wantNum == gotNum {
		return
	}

	t.Fatalf("stale fixture: %s=%q is set, but the applied fixture reports %q for the "+
		"corresponding output. TF_VAR_* values are not part of the fixture content hash "+
		"(test/testutil/fixture/hash.go hashes file contents, and computeEffectiveHash adds "+
		"only the project ID), so the harness reused the existing stack without applying and "+
		"the resources gated on %s were never created. Re-run with AURELIAN_DESTROY_FIXTURES=1 "+
		"to force a teardown and redeploy.", envVar, want, got, envVar)
}

// runGCPSubdomainTakeover runs one scan and returns the risks it emitted.
//
// Each call builds its OWN module instance rather than reusing the one in the
// plugin registry, because module config does NOT reset between runs and the
// registry holds exactly one instance:
//
//   - plugin.Register (pkg/plugin/registry.go) stores a single
//     &ModuleWrapper{Module: m}, and plugin.Get hands every caller that same
//     instance.
//   - GCPSubdomainTakeoverModule embeds its config struct and Parameters()
//     returns a pointer into it (subdomain_takeover.go), so Bind writes
//     straight onto the shared instance.
//   - Bind -> setFields (pkg/plugin/bind.go) skips any parameter that is
//     absent from cfg.Args and carries no `default:` tag. resource-id
//     (pkg/plugin/gcp_params.go) is exactly such a parameter.
//
// Net effect on a shared instance: config is last-write-wins across runs. A
// run that passes resource-id leaves it set, and the NEXT run -- which passes
// only project-id -- still sees it and takes Run's direct-resource branch
// (`len(c.ResourceID) > 0`). That made this suite's result depend on subtest
// order. A fresh instance per run is the isolation; do not "simplify" this
// back to a single hoisted module.
//
// The module is wrapped in plugin.ModuleWrapper so the real Bind + PostBind
// path still runs, exactly as it does in production. Do not bypass it by
// calling the inner Run or plugin.Bind directly.
func runGCPSubdomainTakeover(t *testing.T, args map[string]any) []output.AurelianRisk {
	t.Helper()
	mod := &plugin.ModuleWrapper{Module: &recon.GCPSubdomainTakeoverModule{}}
	cfg := plugin.Config{
		Args:    args,
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
	return risks
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

// findRiskByRecordType finds the risk for an exact record name and record type.
//
// ImpactedResourceID has the shape
// "projects/<project>/managedZones/<zone>/rrsets/<record>/<type>", so an exact
// suffix match is required here: every record in a zone ends with that zone's
// apex name, so the substring match in findRiskByRecord would report a match for
// the apex name against any record in the zone.
func findRiskByRecordType(risks []output.AurelianRisk, recordName, recordType string) *output.AurelianRisk {
	suffix := fmt.Sprintf("/rrsets/%s/%s", recordName, recordType)
	for i := range risks {
		if strings.HasSuffix(risks[i].ImpactedResourceID, suffix) {
			return &risks[i]
		}
	}
	return nil
}
