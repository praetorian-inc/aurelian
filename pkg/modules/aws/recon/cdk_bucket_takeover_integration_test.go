//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeCdkProof unmarshals a Risk's proof bytes into a structured capmodel.Proof.
func decodeCdkProof(t *testing.T, risk capmodel.Risk) capmodel.Proof {
	t.Helper()
	var proof capmodel.Proof
	require.NoError(t, json.Unmarshal(risk.Proof, &proof), "proof should decode into capmodel.Proof")
	return proof
}

// cdkSection returns the named proof section, failing if it is absent.
func cdkSection(t *testing.T, proof capmodel.Proof, title string) capmodel.ProofSection {
	t.Helper()
	for _, s := range proof.Sections {
		if s.Title == title {
			return s
		}
	}
	require.Failf(t, "section not found", "proof has no %q section", title)
	return capmodel.ProofSection{}
}

// cdkKeyValueMap flattens a section's key/value rows into a map for assertions.
func cdkKeyValueMap(section capmodel.ProofSection) map[string]string {
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

// cdkParagraphText concatenates the text of every paragraph element in a section.
func cdkParagraphText(section capmodel.ProofSection) string {
	var text string
	for _, el := range section.Elements {
		if el.Paragraph != nil {
			text += el.Paragraph.Text
		}
	}
	return text
}

// cdkDetails returns the decoded "CDK Details" key-values for a risk's proof.
func cdkDetails(t *testing.T, risk capmodel.Risk) map[string]string {
	t.Helper()
	return cdkKeyValueMap(cdkSection(t, decodeCdkProof(t, risk), "CDK Details"))
}

// TestAWSCdkBucketTakeover verifies the LAB-4008 migration: every CDK risk class
// is emitted as a platform capmodel.Risk (not the legacy freeform Risk struct) carrying a
// structured capmodel.Proof. It provisions the cdk-bucket-takeover fixture, runs
// the module, and asserts the new contract for each detection scenario.
func TestAWSCdkBucketTakeover(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/cdk-bucket-takeover")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "cdk-bucket-takeover")
	if !ok {
		t.Fatal("cdk-bucket-takeover module not registered")
	}

	qualifier := fixture.Output("qualifier")
	qualifierNoBucket := fixture.Output("qualifier_no_bucket")
	qualifierNoSSM := fixture.Output("qualifier_no_ssm")
	accountID := fixture.Output("account_id")
	region := fixture.Output("region")

	cfg := plugin.Config{
		Args: map[string]any{
			"regions":        []string{region},
			"cdk-qualifiers": []string{qualifier, qualifierNoBucket, qualifierNoSSM},
		},
		Context: context.Background(),
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	// The migrated module emits capmodel.Risk values.
	var risks []capmodel.Risk
	for m := range p2.Range() {
		if r, ok := m.(capmodel.Risk); ok {
			risks = append(risks, r)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "expected at least one emitted capmodel.Risk")

	accountArn := "arn:aws:iam::" + accountID + ":root"

	// findRisk locates a risk by name and the Qualifier carried in its proof's
	// "CDK Details" section (the module scans every qualifier in the account).
	findRisk := func(name, qual string) *capmodel.Risk {
		for i := range risks {
			if risks[i].Name != name {
				continue
			}
			if cdkDetails(t, risks[i])["Qualifier"] == qual {
				return &risks[i]
			}
		}
		return nil
	}

	t.Run("detects outdated bootstrap version", func(t *testing.T) {
		risk := findRisk("cdk-bootstrap-outdated", qualifier)
		require.NotNil(t, risk, "expected cdk-bootstrap-outdated risk for qualifier %s", qualifier)
		assert.Equal(t, "TH", risk.Status)
		assert.Equal(t, "aurelian", risk.Source)
		assert.Equal(t, accountArn, risk.TargetName)

		kv := cdkDetails(t, *risk)
		assert.Equal(t, accountID, kv["Account ID"])
		assert.Equal(t, region, kv["Region"])
		assert.NotEqual(t, "Missing", kv["Bootstrap Version"], "outdated bootstrap should carry a numeric version")

		summary := cdkParagraphText(cdkSection(t, decodeCdkProof(t, *risk), "Summary"))
		assert.Contains(t, summary, "20")
	})

	t.Run("detects missing bootstrap version", func(t *testing.T) {
		risk := findRisk("cdk-bootstrap-missing", qualifierNoSSM)
		require.NotNil(t, risk, "expected cdk-bootstrap-missing risk for qualifier %s", qualifierNoSSM)
		assert.Equal(t, "TM", risk.Status)
		assert.Equal(t, "aurelian", risk.Source)
		assert.Equal(t, accountArn, risk.TargetName)

		kv := cdkDetails(t, *risk)
		assert.Equal(t, accountID, kv["Account ID"])
		assert.Equal(t, region, kv["Region"])
		assert.Equal(t, "Missing", kv["Bootstrap Version"])

		summary := cdkParagraphText(cdkSection(t, decodeCdkProof(t, *risk), "Summary"))
		assert.Contains(t, summary, "not found")
	})

	t.Run("detects missing bucket takeover", func(t *testing.T) {
		risk := findRisk("cdk-bucket-takeover", qualifierNoBucket)
		require.NotNil(t, risk, "expected cdk-bucket-takeover risk for qualifier %s", qualifierNoBucket)
		assert.Equal(t, "TH", risk.Status)
		assert.Equal(t, "aurelian", risk.Source)
		assert.Equal(t, accountArn, risk.TargetName)

		kv := cdkDetails(t, *risk)
		assert.Equal(t, accountID, kv["Account ID"])
		assert.Equal(t, region, kv["Region"])
		assert.Contains(t, kv["Bucket Name"], qualifierNoBucket)

		summary := cdkParagraphText(cdkSection(t, decodeCdkProof(t, *risk), "Summary"))
		assert.Contains(t, summary, "missing")
	})

	t.Run("detects unrestricted policy on file publishing role", func(t *testing.T) {
		risk := findRisk("cdk-policy-unrestricted", qualifier)
		require.NotNil(t, risk, "expected cdk-policy-unrestricted risk for qualifier %s", qualifier)
		assert.Equal(t, "TM", risk.Status)
		assert.Equal(t, "aurelian", risk.Source)
		assert.Equal(t, accountArn, risk.TargetName)

		kv := cdkDetails(t, *risk)
		assert.Equal(t, accountID, kv["Account ID"])
		assert.Equal(t, region, kv["Region"])
		assert.Contains(t, kv["Role Name"], qualifier)

		summary := cdkParagraphText(cdkSection(t, decodeCdkProof(t, *risk), "Summary"))
		assert.Contains(t, summary, "FilePublishingRole")
	})

	t.Run("no duplicate risks per qualifier", func(t *testing.T) {
		type riskKey struct {
			Name      string
			Qualifier string
		}
		counts := make(map[riskKey]int)
		for i := range risks {
			qual := cdkDetails(t, risks[i])["Qualifier"]
			counts[riskKey{risks[i].Name, qual}]++
		}
		for key, count := range counts {
			assert.Equal(t, 1, count,
				"risk %q for qualifier %q appeared %d times, expected exactly 1",
				key.Name, key.Qualifier, count)
		}
	})

	t.Run("all risks satisfy the capmodel contract", func(t *testing.T) {
		validStatuses := map[string]bool{"TI": true, "TL": true, "TM": true, "TH": true, "TC": true}
		for i := range risks {
			assert.Equal(t, "aurelian", risks[i].Source, "risk %s has wrong source", risks[i].Name)
			assert.Equal(t, accountArn, risks[i].TargetName, "risk %s has wrong target", risks[i].Name)
			assert.NotEmpty(t, risks[i].Proof, "risk %s has empty proof", risks[i].Name)
			assert.Contains(t, validStatuses, risks[i].Status,
				"risk %s has out-of-contract status %q (want one of TI/TL/TM/TH/TC)", risks[i].Name, risks[i].Status)

			proof := decodeCdkProof(t, risks[i])
			assert.Equal(t, "v1.0.0", proof.Format, "risk %s proof has wrong format", risks[i].Name)

			kv := cdkKeyValueMap(cdkSection(t, proof, "CDK Details"))
			assert.NotEmpty(t, kv, "risk %s has empty CDK Details section", risks[i].Name)
			assert.Equal(t, accountID, kv["Account ID"], "risk %s has wrong account", risks[i].Name)
			assert.Equal(t, region, kv["Region"], "risk %s has wrong region", risks[i].Name)
		}
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		cancelCfg := plugin.Config{
			Args: map[string]any{
				"regions":        []string{region},
				"cdk-qualifiers": []string{qualifier},
			},
			Context: ctx,
		}
		p1 := pipeline.From(cancelCfg)
		p2 := pipeline.New[model.AurelianModel]()
		pipeline.Pipe(p1, mod.Run, p2)
		cancelResults, cancelErr := p2.Collect()
		assert.Error(t, cancelErr, "expected error from cancelled context")
		assert.Empty(t, cancelResults, "expected no results from cancelled context")
	})
}
