package dnstakeover

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeProof unmarshals a Risk's Proof bytes into a structured capmodel.Proof.
func decodeProof(t *testing.T, risk capmodel.Risk) capmodel.Proof {
	t.Helper()
	var proof capmodel.Proof
	require.NoError(t, json.Unmarshal(risk.Proof, &proof))
	return proof
}

// sectionByTitle returns the named proof section, requiring it to exist.
func sectionByTitle(t *testing.T, proof capmodel.Proof, title string) capmodel.ProofSection {
	t.Helper()
	for _, s := range proof.Sections {
		if s.Title == title {
			return s
		}
	}
	require.Failf(t, "section not found", "proof has no %q section", title)
	return capmodel.ProofSection{}
}

// keyValueMap flattens a section's key/value rows into a map for assertions.
func keyValueMap(t *testing.T, section capmodel.ProofSection) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, el := range section.Elements {
		if el.KeyValue == nil {
			continue
		}
		for _, row := range el.KeyValue.Rows {
			out[row.Key] = row.Value
		}
	}
	return out
}

// listLabels collects the labels of every list item across a section's elements.
func listLabels(section capmodel.ProofSection) []string {
	var labels []string
	for _, el := range section.Elements {
		if el.List == nil {
			continue
		}
		for _, item := range el.List.Items {
			labels = append(labels, item.Label)
		}
	}
	return labels
}

// paragraphText concatenates the text of every paragraph element in a section.
func paragraphText(section capmodel.ProofSection) string {
	var text string
	for _, el := range section.Elements {
		if el.Paragraph != nil {
			text += el.Paragraph.Text
		}
	}
	return text
}

func TestNewTakeoverRisk(t *testing.T) {
	cases := []struct {
		name           string
		finding        takeoverFinding
		wantStatus     string
		wantTargetName string
		wantDetailRows map[string]string // checker-specific rows that must be present
	}{
		{
			name: "elastic beanstalk subdomain takeover",
			finding: takeoverFinding{
				riskName:  "Elastic Beanstalk Subdomain Takeover",
				severity:  output.RiskSeverityHigh,
				accountID: "123456789012",
				rec: Route53Record{
					ZoneID:     "Z1EB",
					ZoneName:   "example.com",
					RecordName: "app.example.com",
					Type:       "CNAME",
					Values:     []string{"myapp.us-east-2.elasticbeanstalk.com"},
				},
				summary: "EB takeover summary",
				detailRows: []capmodel.ProofKeyValueRow{
					{Key: "CNAME Target", Value: "myapp.us-east-2.elasticbeanstalk.com"},
					{Key: "EB Prefix", Value: "myapp"},
					{Key: "EB Region", Value: "us-east-2"},
				},
				impact:         "EB impact",
				recommendation: []string{"Remove the stale CNAME record."},
				references:     ebReferences,
			},
			wantStatus:     "TH",
			wantTargetName: "app.example.com",
			wantDetailRows: map[string]string{
				"CNAME Target": "myapp.us-east-2.elasticbeanstalk.com",
				"EB Prefix":    "myapp",
				"EB Region":    "us-east-2",
			},
		},
		{
			name: "dangling elastic ip a record",
			finding: takeoverFinding{
				riskName:  "Dangling Elastic IP A Record",
				severity:  output.RiskSeverityMedium,
				accountID: "123456789012",
				rec: Route53Record{
					ZoneID:     "Z1EIP",
					ZoneName:   "example.com",
					RecordName: "vpn.example.com",
					Type:       "A",
					Values:     []string{"52.1.2.3"},
				},
				summary: "EIP takeover summary",
				detailRows: []capmodel.ProofKeyValueRow{
					{Key: "Dangling IP", Value: "52.1.2.3"},
					{Key: "AWS Region", Value: "us-east-1"},
					{Key: "AWS Service", Value: "EC2"},
				},
				impact:         "EIP impact",
				recommendation: []string{"Remove the stale A record."},
				references:     eipReferences,
			},
			wantStatus:     "TM",
			wantTargetName: "vpn.example.com",
			wantDetailRows: map[string]string{
				"Dangling IP": "52.1.2.3",
				"AWS Region":  "us-east-1",
				"AWS Service": "EC2",
			},
		},
		{
			name: "dangling ns delegation takeover",
			finding: takeoverFinding{
				riskName:  "Dangling NS Delegation Takeover",
				severity:  output.RiskSeverityHigh,
				accountID: "123456789012",
				rec: Route53Record{
					ZoneID:     "Z1NS",
					ZoneName:   "example.com",
					RecordName: "sub.example.com",
					Type:       "NS",
					Values:     []string{"ns-1.awsdns-01.org", "ns-2.awsdns-02.net"},
				},
				summary: "NS takeover summary",
				detailRows: []capmodel.ProofKeyValueRow{
					{Key: "Nameservers", Value: "ns-1.awsdns-01.org, ns-2.awsdns-02.net"},
					{Key: "Query Error", Value: "NXDOMAIN"},
				},
				impact:         "NS impact",
				recommendation: []string{"Remove the stale NS delegation record."},
				references:     nsReferences,
			},
			wantStatus:     "TH",
			wantTargetName: "sub.example.com",
			wantDetailRows: map[string]string{
				"Nameservers": "ns-1.awsdns-01.org, ns-2.awsdns-02.net",
				"Query Error": "NXDOMAIN",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			risk, err := NewTakeoverRisk(tc.finding)
			require.NoError(t, err)

			assert.Equal(t, tc.finding.riskName, risk.Name)
			assert.Equal(t, "aurelian", risk.Source)
			assert.Equal(t, tc.wantStatus, risk.Status)
			assert.Equal(t, tc.wantTargetName, risk.TargetName)
			assert.Nil(t, risk.Target)
			assert.NotEmpty(t, risk.Proof)

			proof := decodeProof(t, risk)
			assert.Equal(t, "v1.0.0", proof.Format)

			// Section ordering: Summary, Record Details, Impact, Recommendation, References.
			titles := make([]string, 0, len(proof.Sections))
			for _, s := range proof.Sections {
				titles = append(titles, s.Title)
			}
			assert.Equal(t,
				[]string{"Summary", "Record Details", "Impact", "Recommendation", "References"},
				titles,
			)

			details := keyValueMap(t, sectionByTitle(t, proof, "Record Details"))

			// Common Route53 rows.
			rec := tc.finding.rec
			assert.Equal(t, rec.ZoneName, details["Zone Name"])
			assert.Equal(t, rec.ZoneID, details["Zone ID"])
			assert.Equal(t, rec.RecordName, details["Record Name"])
			assert.Equal(t, rec.Type, details["Record Type"])
			assert.NotEmpty(t, details["Record Values"])
			assert.Equal(t, tc.finding.accountID, details["Account ID"])

			// Route53 ARN row preserves the legacy ImpactedResourceID value.
			wantARN := "arn:aws:route53:::hostedzone/" + rec.ZoneID +
				"/recordset/" + rec.RecordName + "/" + rec.Type
			assert.Equal(t, wantARN, details["Route53 ARN"])

			// Checker-specific rows.
			for key, want := range tc.wantDetailRows {
				assert.Equal(t, want, details[key], "detail row %q", key)
			}

			assert.NotEmpty(t, paragraphText(sectionByTitle(t, proof, "Summary")))
			assert.NotEmpty(t, paragraphText(sectionByTitle(t, proof, "Impact")))
			assert.NotEmpty(t, listLabels(sectionByTitle(t, proof, "Recommendation")))
			assert.NotEmpty(t, listLabels(sectionByTitle(t, proof, "References")))
		})
	}
}

func TestSeverityToStatus(t *testing.T) {
	cases := map[string]string{
		"critical": "TC",
		"high":     "TH",
		"medium":   "TM",
		"low":      "TL",
		"info":     "TI",
		"":         "TI",
		"bogus":    "TI",
	}
	for sev, want := range cases {
		assert.Equalf(t, want, severityToStatus(output.RiskSeverity(sev)), "severity %q", sev)
	}
}
