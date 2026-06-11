package cdk

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

func testRole() RoleInfo {
	return RoleInfo{
		RoleName:   "cdk-hnb659fds-file-publishing-role-123456789012-us-east-1",
		BucketName: "cdk-hnb659fds-assets-123456789012-us-east-1",
		Qualifier:  "hnb659fds",
		Region:     "us-east-1",
		AccountID:  "123456789012",
	}
}

func TestNewBucketTakeoverRisk(t *testing.T) {
	role := testRole()
	risk, err := NewBucketTakeoverRisk(role)
	require.NoError(t, err)

	assert.Equal(t, "cdk-bucket-takeover", risk.Name)
	assert.Equal(t, "aurelian", risk.Source)
	assert.Equal(t, "TH", risk.Status)
	assert.Equal(t, "arn:aws:iam::123456789012:root", risk.TargetName)

	proof := decodeProof(t, risk)
	assert.Equal(t, "v1.0.0", proof.Format)

	kv := keyValueMap(t, sectionByTitle(t, proof, "CDK Details"))
	assert.Equal(t, "123456789012", kv["Account ID"])
	assert.Equal(t, "us-east-1", kv["Region"])
	assert.Equal(t, "hnb659fds", kv["Qualifier"])
	assert.Equal(t, role.RoleName, kv["Role Name"])
	assert.Equal(t, role.BucketName, kv["Bucket Name"])

	summary := paragraphText(sectionByTitle(t, proof, "Summary"))
	assert.Contains(t, summary, role.BucketName)
	assert.Contains(t, summary, role.RoleName)
	assert.Contains(t, summary, "us-east-1")
	assert.NotEmpty(t, paragraphText(sectionByTitle(t, proof, "Impact")))
	assert.NotEmpty(t, listLabels(sectionByTitle(t, proof, "Recommendation")))
	assert.NotEmpty(t, listLabels(sectionByTitle(t, proof, "References")))
}

func TestNewBucketHijackedRisk(t *testing.T) {
	role := testRole()
	risk, err := NewBucketHijackedRisk(role)
	require.NoError(t, err)

	assert.Equal(t, "cdk-bucket-hijacked", risk.Name)
	assert.Equal(t, "aurelian", risk.Source)
	assert.Equal(t, "TM", risk.Status)
	assert.Equal(t, "arn:aws:iam::123456789012:root", risk.TargetName)

	proof := decodeProof(t, risk)
	kv := keyValueMap(t, sectionByTitle(t, proof, "CDK Details"))
	assert.Equal(t, "hnb659fds", kv["Qualifier"])
	assert.Equal(t, role.BucketName, kv["Bucket Name"])

	summary := paragraphText(sectionByTitle(t, proof, "Summary"))
	assert.Contains(t, summary, role.BucketName)
	assert.Contains(t, summary, "different account")
}

func TestNewPolicyRisk(t *testing.T) {
	role := testRole()
	risk, err := NewPolicyRisk(role)
	require.NoError(t, err)

	assert.Equal(t, "cdk-policy-unrestricted", risk.Name)
	assert.Equal(t, "aurelian", risk.Source)
	assert.Equal(t, "TM", risk.Status)
	assert.Equal(t, "arn:aws:iam::123456789012:root", risk.TargetName)

	proof := decodeProof(t, risk)
	kv := keyValueMap(t, sectionByTitle(t, proof, "CDK Details"))
	assert.Equal(t, "hnb659fds", kv["Qualifier"])
	assert.Equal(t, role.RoleName, kv["Role Name"])

	summary := paragraphText(sectionByTitle(t, proof, "Summary"))
	assert.Contains(t, summary, "FilePublishingRole")
	assert.Contains(t, summary, role.RoleName)

	rec := listLabels(sectionByTitle(t, proof, "Recommendation"))
	require.NotEmpty(t, rec)
	assert.Contains(t, rec[0], "us-east-1")
	assert.Contains(t, rec[0], "cdk bootstrap")
}

func TestNewBootstrapRisk_Outdated(t *testing.T) {
	role := testRole()
	info := BootstrapInfo{HasVersion: true, Version: 14}
	risk, err := NewBootstrapRisk(role, info)
	require.NoError(t, err)

	assert.Equal(t, "cdk-bootstrap-outdated", risk.Name)
	assert.Equal(t, "aurelian", risk.Source)
	assert.Equal(t, "TH", risk.Status)
	assert.Equal(t, "arn:aws:iam::123456789012:root", risk.TargetName)

	proof := decodeProof(t, risk)
	kv := keyValueMap(t, sectionByTitle(t, proof, "CDK Details"))
	assert.Equal(t, "14", kv["Bootstrap Version"])
	assert.Equal(t, "hnb659fds", kv["Qualifier"])

	summary := paragraphText(sectionByTitle(t, proof, "Summary"))
	assert.Contains(t, summary, "14")
	assert.Contains(t, summary, "us-east-1")
}

func TestNewBootstrapRisk_Missing(t *testing.T) {
	role := testRole()
	info := BootstrapInfo{HasVersion: false}
	risk, err := NewBootstrapRisk(role, info)
	require.NoError(t, err)

	assert.Equal(t, "cdk-bootstrap-missing", risk.Name)
	assert.Equal(t, "aurelian", risk.Source)
	assert.Equal(t, "TM", risk.Status)

	proof := decodeProof(t, risk)
	kv := keyValueMap(t, sectionByTitle(t, proof, "CDK Details"))
	assert.Equal(t, "Missing", kv["Bootstrap Version"])

	summary := paragraphText(sectionByTitle(t, proof, "Summary"))
	assert.Contains(t, summary, "not found")
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
