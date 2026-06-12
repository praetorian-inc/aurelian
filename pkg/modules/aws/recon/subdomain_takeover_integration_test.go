//go:build integration

package recon

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordDetails flattens the "Record Details" key/value section into a map.
// decodeProof is shared with cloudfront_s3_takeover_integration_test.go.
func recordDetails(t *testing.T, risk capmodel.Risk) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, s := range decodeProof(t, risk).Sections {
		if s.Title != "Record Details" {
			continue
		}
		for _, el := range s.Elements {
			if el.KeyValue == nil {
				continue
			}
			for _, row := range el.KeyValue.Rows {
				out[row.Key] = row.Value
			}
		}
	}
	return out
}

// sectionText concatenates paragraph text and list labels of the named section.
func sectionText(t *testing.T, risk capmodel.Risk, title string) string {
	t.Helper()
	var text string
	for _, s := range decodeProof(t, risk).Sections {
		if s.Title != title {
			continue
		}
		for _, el := range s.Elements {
			if el.Paragraph != nil {
				text += el.Paragraph.Text
			}
			if el.List != nil {
				for _, item := range el.List.Items {
					text += item.Label
				}
			}
		}
	}
	return text
}

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

	var risks []capmodel.Risk
	for m := range p2.Range() {
		if r, ok := m.(capmodel.Risk); ok {
			risks = append(risks, r)
		}
	}
	require.NoError(t, p2.Wait())

	// The module scans ALL public hosted zones. Filter to risks from our test zone
	// via the "Route53 ARN" detail row, which encodes the hosted zone ID.
	zoneID := fixture.Output("zone_id")
	var testRisks []capmodel.Risk
	for _, r := range risks {
		if strings.Contains(recordDetails(t, r)["Route53 ARN"], zoneID) {
			testRisks = append(testRisks, r)
		}
	}
	require.NotEmpty(t, testRisks, "expected at least one risk from the test zone %s", zoneID)

	// findByName returns the first test-zone risk with the given human-readable Name
	// whose Record Name matches recordName.
	findByName := func(name, recordName string) *capmodel.Risk {
		for i := range testRisks {
			if testRisks[i].Name == name &&
				recordDetails(t, testRisks[i])["Record Name"] == recordName {
				return &testRisks[i]
			}
		}
		return nil
	}

	// --- Per-checker detection subtests ---

	t.Run("detects EB CNAME takeover", func(t *testing.T) {
		ebRecord := fixture.Output("eb_cname_record_name")
		matched := findByName("Elastic Beanstalk Subdomain Takeover", ebRecord)
		require.NotNilf(t, matched, "expected EB takeover risk for record %s", ebRecord)

		assert.Equal(t, "TH", matched.Status)

		details := recordDetails(t, *matched)
		assert.Contains(t, details["CNAME Target"], "elasticbeanstalk.com",
			"details should reference EB CNAME target")
		assert.Equal(t, fixture.Output("eb_cname_prefix"), details["EB Prefix"],
			"details should contain the EB prefix")
		assert.Equal(t, "us-east-2", details["EB Region"],
			"details should contain the EB region")
		assert.NotEmpty(t, sectionText(t, *matched, "Summary"))
		assert.NotEmpty(t, sectionText(t, *matched, "Recommendation"))
		assert.NotEmpty(t, sectionText(t, *matched, "References"))
	})

	t.Run("detects EIP dangling A record", func(t *testing.T) {
		eipRecord := fixture.Output("eip_a_record_name")
		matched := findByName("Dangling Elastic IP A Record", eipRecord)
		require.NotNilf(t, matched, "expected EIP dangling risk for record %s", eipRecord)

		assert.Equal(t, "TM", matched.Status)

		details := recordDetails(t, *matched)
		assert.Equal(t, fixture.Output("dangling_ip"), details["Dangling IP"],
			"details should contain the dangling IP")
		assert.NotEmpty(t, details["AWS Region"], "details should contain the AWS region")
		assert.NotEmpty(t, details["AWS Service"], "details should contain the AWS service")
		assert.NotEmpty(t, sectionText(t, *matched, "Summary"))
		assert.NotEmpty(t, sectionText(t, *matched, "Recommendation"))
		assert.NotEmpty(t, sectionText(t, *matched, "References"))
	})

	t.Run("detects NS delegation takeover", func(t *testing.T) {
		nsRecord := fixture.Output("ns_record_name")
		matched := findByName("Dangling NS Delegation Takeover", nsRecord)
		require.NotNilf(t, matched, "expected NS delegation risk for record %s", nsRecord)

		assert.Equal(t, "TH", matched.Status)

		details := recordDetails(t, *matched)
		assert.NotEmpty(t, details["Nameservers"], "details should list dangling nameservers")

		validErrors := map[string]bool{"NXDOMAIN": true, "SERVFAIL": true, "REFUSED": true}
		assert.Truef(t, validErrors[details["Query Error"]],
			"query error should be NXDOMAIN, SERVFAIL, or REFUSED, got %q", details["Query Error"])
		assert.NotEmpty(t, sectionText(t, *matched, "Summary"))
		assert.NotEmpty(t, sectionText(t, *matched, "Recommendation"))
		assert.NotEmpty(t, sectionText(t, *matched, "References"))
	})

	// --- Negative testing ---

	t.Run("safe CNAME does not trigger finding", func(t *testing.T) {
		safeCname := fixture.Output("safe_cname_record_name")
		for _, r := range testRisks {
			assert.NotEqualf(t, safeCname, recordDetails(t, r)["Record Name"],
				"safe CNAME %s should not trigger a finding (got %s)", safeCname, r.Name)
		}
	})

	t.Run("safe A record does not trigger finding", func(t *testing.T) {
		safeA := fixture.Output("safe_a_record_name")
		for _, r := range testRisks {
			assert.NotEqualf(t, safeA, recordDetails(t, r)["Record Name"],
				"safe A record %s should not trigger a finding (got %s)", safeA, r.Name)
		}
	})

	// --- Cross-cutting contract validation ---

	t.Run("all risks satisfy the capmodel.Risk contract", func(t *testing.T) {
		validNames := map[string]bool{
			"Elastic Beanstalk Subdomain Takeover": true,
			"Dangling Elastic IP A Record":         true,
			"Dangling NS Delegation Takeover":      true,
		}
		validStatus := map[string]bool{"TC": true, "TH": true, "TM": true, "TL": true, "TI": true}

		for _, r := range testRisks {
			assert.Truef(t, validNames[r.Name], "unexpected risk name %q", r.Name)
			assert.Equalf(t, "aurelian", r.Source, "risk %q should have Source=aurelian", r.Name)
			assert.Truef(t, validStatus[r.Status], "risk %q has invalid status %q", r.Name, r.Status)
			assert.NotEmptyf(t, r.TargetName, "risk %q should have a TargetName", r.Name)
			assert.NotEmptyf(t, r.Proof, "risk %q should have a non-empty Proof", r.Name)

			details := recordDetails(t, r)
			assert.Equalf(t, zoneID, details["Zone ID"], "risk %q Zone ID mismatch", r.Name)
			assert.NotEmptyf(t, details["Zone Name"], "risk %q missing Zone Name", r.Name)
			assert.NotEmptyf(t, details["Record Name"], "risk %q missing Record Name", r.Name)
			assert.NotEmptyf(t, details["Record Type"], "risk %q missing Record Type", r.Name)
			assert.NotEmptyf(t, details["Account ID"], "risk %q missing Account ID", r.Name)
			assert.Truef(t,
				strings.HasPrefix(details["Route53 ARN"], "arn:aws:route53:::hostedzone/"),
				"risk %q Route53 ARN %q should start with arn:aws:route53:::hostedzone/",
				r.Name, details["Route53 ARN"])
		}
	})
}
