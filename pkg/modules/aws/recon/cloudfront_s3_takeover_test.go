package recon

import (
	"encoding/json"
	"testing"

	cf "github.com/praetorian-inc/aurelian/pkg/aws/cloudfront"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTakeoverRisk_MediumSeverity(t *testing.T) {
	finding := cf.Finding{
		VulnerableDistribution: cf.VulnerableDistribution{
			DistributionID:     "EDIST_MEDIUM",
			DistributionDomain: "d-med.cloudfront.net",
			MissingBucket:      "orphaned-bucket",
			OriginDomain:       "orphaned-bucket.s3.amazonaws.com",
			OriginID:           "S3-orphaned",
			AccountID:          "123456789012",
		},
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		require.NoError(t, buildTakeoverRisk(finding, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	risk := items[0].(output.AurelianRisk)
	assert.Equal(t, "cloudfront-s3-takeover", risk.Name)
	assert.Equal(t, output.RiskSeverityMedium, risk.Severity)
	assert.Equal(t, "EDIST_MEDIUM", risk.ImpactedARN)
}

func TestBuildTakeoverRisk_HighSeverity(t *testing.T) {
	finding := cf.Finding{
		VulnerableDistribution: cf.VulnerableDistribution{
			DistributionID:     "EDIST_HIGH",
			DistributionDomain: "d-high.cloudfront.net",
			Aliases:            []string{"app.example.com"},
			MissingBucket:      "taken-bucket",
			OriginDomain:       "taken-bucket.s3.amazonaws.com",
			OriginID:           "S3-taken",
			AccountID:          "123456789012",
		},
		Route53Records: []cf.Route53Record{
			{
				ZoneID:     "Z1",
				ZoneName:   "example.com",
				RecordName: "app.example.com",
				RecordType: "A",
				Value:      "d-high.cloudfront.net",
			},
		},
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		require.NoError(t, buildTakeoverRisk(finding, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	risk := items[0].(output.AurelianRisk)
	assert.Equal(t, output.RiskSeverityHigh, risk.Severity,
		"Route53 records pointing to the distribution should elevate severity to High")
	assert.Equal(t, "EDIST_HIGH", risk.ImpactedARN)
}

func TestBuildTakeoverRisk_ContextFields(t *testing.T) {
	finding := cf.Finding{
		VulnerableDistribution: cf.VulnerableDistribution{
			DistributionID:     "EDIST_CTX",
			DistributionDomain: "d-ctx.cloudfront.net",
			Aliases:            []string{"site.example.com"},
			MissingBucket:      "ctx-bucket",
			OriginDomain:       "ctx-bucket.s3.amazonaws.com",
			OriginID:           "S3-ctx",
			AccountID:          "123456789012",
		},
		Route53Records: []cf.Route53Record{
			{RecordName: "site.example.com", RecordType: "A", Value: "d-ctx.cloudfront.net"},
		},
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		require.NoError(t, buildTakeoverRisk(finding, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	risk := items[0].(output.AurelianRisk)

	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &ctx))

	assert.Equal(t, "EDIST_CTX", ctx["distribution_id"])
	assert.Equal(t, "d-ctx.cloudfront.net", ctx["distribution_domain"])
	assert.Equal(t, "ctx-bucket", ctx["missing_bucket"])
	assert.Equal(t, "ctx-bucket.s3.amazonaws.com", ctx["origin_domain"])
	assert.Equal(t, "S3-ctx", ctx["origin_id"])
	assert.NotEmpty(t, ctx["description"])
	assert.NotEmpty(t, ctx["impact"])
	assert.NotEmpty(t, ctx["recommendation"])
	assert.NotNil(t, ctx["affected_domains"])
	assert.NotNil(t, ctx["route53_records"])
}

func TestBuildTakeoverRisk_AliasOnlyDomains(t *testing.T) {
	finding := cf.Finding{
		VulnerableDistribution: cf.VulnerableDistribution{
			DistributionID:     "EDIST_ALIAS",
			DistributionDomain: "d-alias.cloudfront.net",
			Aliases:            []string{"cdn.example.com", "static.example.com"},
			MissingBucket:      "alias-bucket",
			OriginDomain:       "alias-bucket.s3.amazonaws.com",
			OriginID:           "S3-alias",
			AccountID:          "123456789012",
		},
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		require.NoError(t, buildTakeoverRisk(finding, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	risk := items[0].(output.AurelianRisk)
	assert.Equal(t, output.RiskSeverityMedium, risk.Severity,
		"aliases without Route53 records should remain Medium")

	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &ctx))

	desc := ctx["description"].(string)
	assert.Contains(t, desc, "alias domain(s)")
	assert.Contains(t, desc, "cdn.example.com")
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
		records := []cf.Route53Record{
			{RecordName: "x.com"},
			{RecordName: "y.com"},
		}
		domains := collectAffectedDomains(nil, records)
		assert.Equal(t, []string{"x.com", "y.com"}, domains)
	})

	t.Run("Route53 records before aliases", func(t *testing.T) {
		records := []cf.Route53Record{{RecordName: "r53.com"}}
		domains := collectAffectedDomains([]string{"alias.com"}, records)
		assert.Equal(t, []string{"r53.com", "alias.com"}, domains)
	})

	t.Run("deduplicates overlapping records and aliases", func(t *testing.T) {
		records := []cf.Route53Record{
			{RecordName: "shared.com"},
			{RecordName: "shared.com"},
		}
		domains := collectAffectedDomains([]string{"shared.com", "unique.com"}, records)
		assert.Equal(t, []string{"shared.com", "unique.com"}, domains)
	})
}
