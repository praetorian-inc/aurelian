package cloudfront

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

func TestNewTakeoverRisk_MediumSeverity(t *testing.T) {
	finding := Finding{
		VulnerableDistribution: VulnerableDistribution{
			DistributionID:     "EDIST_MEDIUM",
			DistributionDomain: "d-med.cloudfront.net",
			MissingBucket:      "orphaned-bucket",
			OriginDomain:       "orphaned-bucket.s3.amazonaws.com",
			OriginID:           "S3-orphaned",
			AccountID:          "123456789012",
		},
	}

	risk, err := NewTakeoverRisk(finding)
	require.NoError(t, err)

	assert.Equal(t, "CloudFront S3 Origin Takeover", risk.Name)
	assert.Equal(t, "aurelian", risk.Source)
	assert.Equal(t, "TM", risk.Status)
	assert.Equal(t, "d-med.cloudfront.net", risk.TargetName,
		"with no affected domains TargetName falls back to the distribution domain")

	proof := decodeProof(t, risk)
	kv := keyValueMap(t, sectionByTitle(t, proof, "Distribution Details"))
	assert.Equal(t, "EDIST_MEDIUM", kv["Distribution ID"])
	assert.Equal(t, "orphaned-bucket", kv["Missing Bucket"])
}

func TestNewTakeoverRisk_HighSeverity(t *testing.T) {
	finding := Finding{
		VulnerableDistribution: VulnerableDistribution{
			DistributionID:     "EDIST_HIGH",
			DistributionDomain: "d-high.cloudfront.net",
			Aliases:            []string{"app.example.com"},
			MissingBucket:      "taken-bucket",
			OriginDomain:       "taken-bucket.s3.amazonaws.com",
			OriginID:           "S3-taken",
			AccountID:          "123456789012",
		},
		Route53Records: []Route53Record{
			{
				ZoneID:     "Z1",
				ZoneName:   "example.com",
				RecordName: "app.example.com",
				RecordType: "A",
				Value:      "d-high.cloudfront.net",
			},
		},
	}

	risk, err := NewTakeoverRisk(finding)
	require.NoError(t, err)

	assert.Equal(t, "TH", risk.Status,
		"Route53 records pointing to the distribution should elevate severity to High")
	assert.Equal(t, "app.example.com", risk.TargetName,
		"TargetName should be the first affected domain")

	proof := decodeProof(t, risk)
	affected := sectionByTitle(t, proof, "Affected Domains")
	assert.Contains(t, listLabels(affected), "app.example.com")

	var hasTable bool
	for _, el := range affected.Elements {
		if el.Table != nil {
			hasTable = true
			require.Len(t, el.Table.Rows, 1)
			assert.Equal(t, "app.example.com", el.Table.Rows[0]["record_name"])
		}
	}
	assert.True(t, hasTable, "Route53 records should produce a table element")
}

func TestNewTakeoverRisk_ProofSections(t *testing.T) {
	finding := Finding{
		VulnerableDistribution: VulnerableDistribution{
			DistributionID:     "EDIST_CTX",
			DistributionDomain: "d-ctx.cloudfront.net",
			Aliases:            []string{"site.example.com"},
			MissingBucket:      "ctx-bucket",
			OriginDomain:       "ctx-bucket.s3.amazonaws.com",
			OriginID:           "S3-ctx",
			AccountID:          "123456789012",
		},
		Route53Records: []Route53Record{
			{RecordName: "site.example.com", RecordType: "A", Value: "d-ctx.cloudfront.net"},
		},
	}

	risk, err := NewTakeoverRisk(finding)
	require.NoError(t, err)
	proof := decodeProof(t, risk)

	assert.Equal(t, "v1.0.0", proof.Format)

	kv := keyValueMap(t, sectionByTitle(t, proof, "Distribution Details"))
	assert.Equal(t, "EDIST_CTX", kv["Distribution ID"])
	assert.Equal(t, "d-ctx.cloudfront.net", kv["Distribution Domain"])
	assert.Equal(t, "ctx-bucket", kv["Missing Bucket"])
	assert.Equal(t, "ctx-bucket.s3.amazonaws.com", kv["Origin Domain"])
	assert.Equal(t, "S3-ctx", kv["Origin ID"])

	assert.NotEmpty(t, paragraphText(sectionByTitle(t, proof, "Summary")))
	assert.NotEmpty(t, paragraphText(sectionByTitle(t, proof, "Impact")))
	assert.NotEmpty(t, listLabels(sectionByTitle(t, proof, "Recommendation")))
	assert.NotEmpty(t, listLabels(sectionByTitle(t, proof, "References")))
	assert.Contains(t, listLabels(sectionByTitle(t, proof, "Affected Domains")), "site.example.com")
}

func TestNewTakeoverRisk_AliasOnlyDomains(t *testing.T) {
	finding := Finding{
		VulnerableDistribution: VulnerableDistribution{
			DistributionID:     "EDIST_ALIAS",
			DistributionDomain: "d-alias.cloudfront.net",
			Aliases:            []string{"cdn.example.com", "static.example.com"},
			MissingBucket:      "alias-bucket",
			OriginDomain:       "alias-bucket.s3.amazonaws.com",
			OriginID:           "S3-alias",
			AccountID:          "123456789012",
		},
	}

	risk, err := NewTakeoverRisk(finding)
	require.NoError(t, err)

	assert.Equal(t, "TM", risk.Status,
		"aliases without Route53 records should remain Medium")
	assert.Equal(t, "cdn.example.com", risk.TargetName,
		"TargetName should be the first alias when there are no Route53 records")

	proof := decodeProof(t, risk)
	desc := paragraphText(sectionByTitle(t, proof, "Summary"))
	assert.Contains(t, desc, "alias domain(s)")
	assert.Contains(t, desc, "cdn.example.com")
}

func TestNewTakeoverRisk_NotOwnedBucket(t *testing.T) {
	finding := Finding{
		VulnerableDistribution: VulnerableDistribution{
			DistributionID:     "EDIST_NOTOWNED",
			DistributionDomain: "d-notowned.cloudfront.net",
			Aliases:            []string{"app.example.com"},
			MissingBucket:      "hijacked-bucket",
			OriginDomain:       "hijacked-bucket.s3.amazonaws.com",
			OriginID:           "S3-hijacked",
			AccountID:          "123456789012",
			BucketState:        BucketExistsNotOwned,
		},
		Route53Records: []Route53Record{
			{RecordName: "app.example.com", RecordType: "A", Value: "d-notowned.cloudfront.net"},
		},
	}

	risk, err := NewTakeoverRisk(finding)
	require.NoError(t, err)

	assert.Equal(t, "TC", risk.Status,
		"bucket owned by another account should be Critical severity")

	proof := decodeProof(t, risk)
	kv := keyValueMap(t, sectionByTitle(t, proof, "Distribution Details"))
	assert.Equal(t, "not_owned", kv["Bucket State"])

	desc := paragraphText(sectionByTitle(t, proof, "Summary"))
	assert.Contains(t, desc, "not owned by this account")
	assert.Contains(t, desc, "app.example.com")
	assert.Contains(t, desc, "Route53 records are actively pointing to this distribution",
		"not-owned bucket with active Route53 records should surface the DNS context")
	assert.Contains(t, paragraphText(sectionByTitle(t, proof, "Impact")), "owned by another account")
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

func TestCollectAffectedDomains(t *testing.T) {
	t.Run("empty inputs", func(t *testing.T) {
		domains := collectAffectedDomains(nil, nil)
		assert.Nil(t, domains)
	})

	t.Run("aliases only", func(t *testing.T) {
		domains := collectAffectedDomains([]string{"a.com", "b.com"}, nil)
		assert.Equal(t, []string{"a.com", "b.com"}, domains)
	})

	t.Run("Route53 records only", func(t *testing.T) {
		records := []Route53Record{
			{RecordName: "x.com"},
			{RecordName: "y.com"},
		}
		domains := collectAffectedDomains(nil, records)
		assert.Equal(t, []string{"x.com", "y.com"}, domains)
	})

	t.Run("Route53 records before aliases", func(t *testing.T) {
		records := []Route53Record{{RecordName: "r53.com"}}
		domains := collectAffectedDomains([]string{"alias.com"}, records)
		assert.Equal(t, []string{"r53.com", "alias.com"}, domains)
	})

	t.Run("deduplicates overlapping records and aliases", func(t *testing.T) {
		records := []Route53Record{
			{RecordName: "shared.com"},
			{RecordName: "shared.com"},
		}
		domains := collectAffectedDomains([]string{"shared.com", "unique.com"}, records)
		assert.Equal(t, []string{"shared.com", "unique.com"}, domains)
	})
}
