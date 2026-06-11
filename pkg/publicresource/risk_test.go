package publicresource

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

// findSection returns the named section and whether it exists.
func findSection(proof capmodel.Proof, title string) (capmodel.ProofSection, bool) {
	for _, s := range proof.Sections {
		if s.Title == title {
			return s, true
		}
	}
	return capmodel.ProofSection{}, false
}

// sectionByTitle returns the named proof section, requiring it to exist.
func sectionByTitle(t *testing.T, proof capmodel.Proof, title string) capmodel.ProofSection {
	t.Helper()
	s, ok := findSection(proof, title)
	require.Truef(t, ok, "proof has no %q section", title)
	return s
}

// keyValueMap flattens a section's key/value rows into a map for assertions.
func keyValueMap(section capmodel.ProofSection) map[string]string {
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

// listLabels collects the labels of every list item across a section.
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

func sampleResource() PublicResource {
	return PublicResource{
		Provider:     "AWS",
		RiskName:     "public-aws-resource",
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "arn:aws:s3:::public-bucket",
		ResourceName: "public-bucket",
		Region:       "us-east-1",
		Scope:        "123456789012",
		ScopeLabel:   "AWS Account",
		Severity:     output.RiskSeverityHigh,
		Summary:      "AWS resource is publicly accessible.",
		Exposure: []Fact{
			{Key: "Access Level", Value: "public"},
			{Key: "Public", Value: "true"},
		},
		Lists: []NamedList{
			{Title: "Allowed Actions", Items: []string{"s3:GetObject"}},
		},
		References: []string{"https://example.com/ref"},
		Properties: map[string]any{"PublicAccessBlock": false},
	}
}

func TestNewRisk_Identity(t *testing.T) {
	risk, err := NewRisk(sampleResource())
	require.NoError(t, err)

	assert.Equal(t, "arn:aws:s3:::public-bucket", risk.TargetName)
	assert.Equal(t, "public-aws-resource", risk.Name)
	assert.Equal(t, "aurelian", risk.Source)
	assert.Equal(t, "TH", risk.Status)
	assert.Empty(t, risk.Title)
	assert.Nil(t, risk.Target)
}

func TestNewRisk_ProofSections(t *testing.T) {
	risk, err := NewRisk(sampleResource())
	require.NoError(t, err)
	proof := decodeProof(t, risk)

	assert.Equal(t, "v1.0.0", proof.Format)

	assert.NotEmpty(t, paragraphText(sectionByTitle(t, proof, "Summary")))

	resource := keyValueMap(sectionByTitle(t, proof, "Resource"))
	assert.Equal(t, "AWS", resource["Provider"])
	assert.Equal(t, "AWS::S3::Bucket", resource["Resource Type"])
	assert.Equal(t, "arn:aws:s3:::public-bucket", resource["Resource ID"])
	assert.Equal(t, "public-bucket", resource["Name"])
	assert.Equal(t, "us-east-1", resource["Region"])
	assert.Equal(t, "123456789012", resource["AWS Account"])

	exposure := keyValueMap(sectionByTitle(t, proof, "Exposure"))
	assert.Equal(t, "public", exposure["Access Level"])
	assert.Equal(t, "true", exposure["Public"])

	assert.Equal(t, []string{"s3:GetObject"}, listLabels(sectionByTitle(t, proof, "Allowed Actions")))

	refs := sectionByTitle(t, proof, "References")
	require.NotEmpty(t, refs.Elements)
	require.NotNil(t, refs.Elements[0].List)
	require.Len(t, refs.Elements[0].List.Items, 1)
	assert.Equal(t, "https://example.com/ref", refs.Elements[0].List.Items[0].Href)

	props := sectionByTitle(t, proof, "Resource Properties")
	require.NotEmpty(t, props.Elements)
	require.NotNil(t, props.Elements[0].CodeBlock)
	assert.Equal(t, "json", props.Elements[0].CodeBlock.Language)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(props.Elements[0].CodeBlock.Content), &decoded))
	assert.Equal(t, false, decoded["PublicAccessBlock"])
}

func TestNewRisk_OptionalSectionsOmitted(t *testing.T) {
	r := PublicResource{
		Provider:     "GCP",
		RiskName:     "public-gcp-resource",
		ResourceType: "compute.googleapis.com/Address",
		ResourceID:   "addr-1",
		ScopeLabel:   "GCP Project",
		Scope:        "proj",
		Severity:     output.RiskSeverityMedium,
		Summary:      "GCP resource has public network exposure.",
		Exposure:     nil,
		Lists:        []NamedList{{Title: "Public IPs", Items: nil}},
		References:   nil,
		Properties:   nil,
	}

	risk, err := NewRisk(r)
	require.NoError(t, err)
	proof := decodeProof(t, risk)

	_, hasSummary := findSection(proof, "Summary")
	_, hasResource := findSection(proof, "Resource")
	assert.True(t, hasSummary)
	assert.True(t, hasResource)

	for _, absent := range []string{"Exposure", "Public IPs", "References", "Resource Properties"} {
		_, ok := findSection(proof, absent)
		assert.Falsef(t, ok, "section %q should be omitted", absent)
	}
}

func TestNewRisk_EmptyFactValuesSkipped(t *testing.T) {
	r := sampleResource()
	r.Exposure = []Fact{
		{Key: "Access Level", Value: "public"},
		{Key: "Empty", Value: ""},
	}

	risk, err := NewRisk(r)
	require.NoError(t, err)
	proof := decodeProof(t, risk)

	exposure := keyValueMap(sectionByTitle(t, proof, "Exposure"))
	assert.Contains(t, exposure, "Access Level")
	assert.NotContains(t, exposure, "Empty")
}

func TestNewRisk_Validation(t *testing.T) {
	t.Run("missing RiskName", func(t *testing.T) {
		r := sampleResource()
		r.RiskName = ""
		_, err := NewRisk(r)
		assert.Error(t, err)
	})

	t.Run("missing ResourceID", func(t *testing.T) {
		r := sampleResource()
		r.ResourceID = ""
		_, err := NewRisk(r)
		assert.Error(t, err)
	})
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

func TestNewRisk_AzureShape(t *testing.T) {
	risk, err := NewRisk(PublicResource{
		Provider:     "Azure",
		RiskName:     "public-azure-resource",
		ResourceType: "Microsoft.Storage/storageAccounts",
		ResourceID:   "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
		ResourceName: "sa",
		Region:       "eastus",
		Scope:        "s",
		ScopeLabel:   "Azure Subscription",
		Severity:     output.RiskSeverityHigh,
		Summary:      "Azure storage account is public.",
		Exposure:     []Fact{{Key: "Template ID", Value: "storage_accounts_public_access"}},
		References:   []string{"https://learn.microsoft.com"},
	})
	require.NoError(t, err)

	assert.Equal(t, "public-azure-resource", risk.Name)
	assert.Equal(t, "TH", risk.Status)
	proof := decodeProof(t, risk)
	exposure := keyValueMap(sectionByTitle(t, proof, "Exposure"))
	assert.Equal(t, "storage_accounts_public_access", exposure["Template ID"])
	resource := keyValueMap(sectionByTitle(t, proof, "Resource"))
	assert.Equal(t, "s", resource["Azure Subscription"])
}

func TestNewRisk_GCPShape(t *testing.T) {
	risk, err := NewRisk(PublicResource{
		Provider:     "GCP",
		RiskName:     "public-anonymous-gcp-resource",
		ResourceType: "run.googleapis.com/Service",
		ResourceID:   "svc-1",
		Scope:        "proj",
		ScopeLabel:   "GCP Project",
		Severity:     output.RiskSeverityHigh,
		Summary:      "GCP resource is reachable and anonymous.",
		Exposure: []Fact{
			{Key: "Public Network", Value: "true"},
			{Key: "Anonymous Access", Value: "true"},
		},
		Lists: []NamedList{{Title: "Public URLs", Items: []string{"https://svc.run.app"}}},
	})
	require.NoError(t, err)

	assert.Equal(t, "public-anonymous-gcp-resource", risk.Name)
	assert.Equal(t, "TH", risk.Status)
	proof := decodeProof(t, risk)
	exposure := keyValueMap(sectionByTitle(t, proof, "Exposure"))
	assert.Equal(t, "true", exposure["Public Network"])
	assert.Equal(t, "true", exposure["Anonymous Access"])
	assert.Equal(t, []string{"https://svc.run.app"}, listLabels(sectionByTitle(t, proof, "Public URLs")))
}
