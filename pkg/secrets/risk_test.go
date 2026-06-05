package secrets

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeProof unmarshals a Risk's Proof bytes into a SecretProof.
func decodeProof(t *testing.T, risk capmodel.Risk) SecretProof {
	t.Helper()
	var proof SecretProof
	require.NoError(t, json.Unmarshal(risk.Proof, &proof))
	return proof
}

// decodeRawProof unmarshals a Risk's Proof bytes into a map so individual key
// presence can be asserted against Guard's expected secrets shape.
func decodeRawProof(t *testing.T, risk capmodel.Risk) map[string]any {
	t.Helper()
	var raw map[string]any
	require.NoError(t, json.Unmarshal(risk.Proof, &raw))
	return raw
}

func validatedResult() SecretScanResult {
	return SecretScanResult{
		ResourceRef:  "arn:aws:lambda:us-east-1:123:function:demo",
		ResourceType: "AWS::Lambda::Function",
		Region:       "us-east-1",
		AccountID:    "123",
		Platform:     "aws",
		Label:        "handler.py",
		Match: &types.Match{
			RuleID:    "np.aws.1",
			RuleName:  "AWS API Key",
			FindingID: "abc123def456",
			Snippet: types.Snippet{
				Before:   []byte("key="),
				Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
				After:    []byte("\n"),
			},
			Location: types.Location{
				Offset: types.OffsetSpan{Start: 4, End: 24},
				Source: types.SourceSpan{
					Start: types.SourcePoint{Line: 1, Column: 5},
					End:   types.SourcePoint{Line: 1, Column: 25},
				},
			},
			ValidationResult: &types.ValidationResult{
				Status:     types.StatusValid,
				Confidence: 0.95,
				Message:    "Key is active",
			},
		},
	}
}

func TestToRisk_RiskFields(t *testing.T) {
	risk, err := validatedResult().ToRisk()
	require.NoError(t, err)

	assert.Equal(t, "aws-secret-aws", risk.Name)
	assert.Equal(t, "aurelian", risk.Source)
	assert.Equal(t, "TH", risk.Status, "validated secret should be High → TH")
	assert.Equal(t, "arn:aws:lambda:us-east-1:123:function:demo:abc123de", risk.TargetName)
	assert.Empty(t, risk.Title)
	assert.Nil(t, risk.Target)
}

func TestToRisk_ProofShape(t *testing.T) {
	risk, err := validatedResult().ToRisk()
	require.NoError(t, err)

	proof := decodeProof(t, risk)
	assert.Equal(t, "v1.0.0", proof.Version)
	assert.Equal(t, "abc123def456", proof.FindingID)
	assert.Equal(t, "AWS API Key", proof.RuleName)
	assert.Equal(t, "np.aws.1", proof.RuleTextID)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123:function:demo", proof.ResourceRef)
	assert.Equal(t, 1, proof.NumMatches)

	require.Len(t, proof.Matches, 1)
	m0 := proof.Matches[0]

	require.Len(t, m0.Provenance, 1)
	prov := m0.Provenance[0]
	assert.Equal(t, "cloud", prov.Kind)
	assert.Equal(t, "aws", prov.Platform)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123:function:demo", prov.ResourceID)
	assert.Equal(t, "AWS::Lambda::Function", prov.ResourceType)
	assert.Equal(t, "us-east-1", prov.Region)
	assert.Equal(t, "123", prov.AccountID)
	assert.Equal(t, "handler.py", prov.Subresource)

	assert.Equal(t, "key=", m0.Snippet.Before)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", m0.Snippet.Matching)
	assert.Equal(t, "\n", m0.Snippet.After)

	assert.Equal(t, int64(4), m0.Location.OffsetSpan.Start)
	assert.Equal(t, int64(24), m0.Location.OffsetSpan.End)
	assert.Equal(t, 1, m0.Location.SourceSpan.Start.Line)
	assert.Equal(t, 5, m0.Location.SourceSpan.Start.Column)
	assert.Equal(t, 1, m0.Location.SourceSpan.End.Line)
	assert.Equal(t, 25, m0.Location.SourceSpan.End.Column)
}

// TestToRisk_ProofKeys asserts every Guard secrets key is present with its exact
// JSON name, so the typed structs stay wire-compatible with Guard's consumer.
func TestToRisk_ProofKeys(t *testing.T) {
	risk, err := validatedResult().ToRisk()
	require.NoError(t, err)

	raw := decodeRawProof(t, risk)
	for _, key := range []string{"version", "finding_id", "rule_name", "rule_text_id", "resource_ref", "num_matches", "matches", "validation"} {
		_, ok := raw[key]
		assert.Truef(t, ok, "proof should contain key %q", key)
	}

	matches := raw["matches"].([]any)
	require.Len(t, matches, 1)
	m0 := matches[0].(map[string]any)
	for _, key := range []string{"provenance", "snippet", "location"} {
		_, ok := m0[key]
		assert.Truef(t, ok, "match should contain key %q", key)
	}

	prov := m0["provenance"].([]any)[0].(map[string]any)
	for _, key := range []string{"kind", "platform", "resource_id", "resource_type", "region", "account_id", "subresource"} {
		_, ok := prov[key]
		assert.Truef(t, ok, "provenance should contain key %q", key)
	}

	location := m0["location"].(map[string]any)
	offset := location["offset_span"].(map[string]any)
	assert.Contains(t, offset, "start")
	assert.Contains(t, offset, "end")
	source := location["source_span"].(map[string]any)
	start := source["start"].(map[string]any)
	assert.Contains(t, start, "line")
	assert.Contains(t, start, "column")
}

func TestToRisk_ValidationPresent(t *testing.T) {
	risk, err := validatedResult().ToRisk()
	require.NoError(t, err)

	proof := decodeProof(t, risk)
	require.NotNil(t, proof.Validation, "validation should be present when ValidationResult is set")
	assert.Equal(t, string(types.StatusValid), proof.Validation.Status)
	assert.Equal(t, 0.95, proof.Validation.Confidence)
	assert.Equal(t, "Key is active", proof.Validation.Message)
}

func TestToRisk_ValidationAbsentWhenNil(t *testing.T) {
	result := SecretScanResult{
		ResourceRef: "arn:aws:s3:::bucket",
		Platform:    "aws",
		Match: &types.Match{
			RuleID:    "np.aws.1",
			RuleName:  "AWS API Key",
			FindingID: "abc123",
		},
	}

	risk, err := result.ToRisk()
	require.NoError(t, err)

	proof := decodeProof(t, risk)
	assert.Nil(t, proof.Validation, "validation should be nil when ValidationResult is nil")

	raw := decodeRawProof(t, risk)
	_, hasValidation := raw["validation"]
	assert.False(t, hasValidation, "validation key should be omitted when nil")
}

func TestToRisk_SeverityBranches(t *testing.T) {
	cases := map[string]struct {
		validation *types.ValidationResult
		wantStatus string
	}{
		"valid → TH":      {&types.ValidationResult{Status: types.StatusValid}, "TH"},
		"invalid → TM":    {&types.ValidationResult{Status: types.StatusInvalid}, "TM"},
		"nil result → TM": {nil, "TM"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result := SecretScanResult{
				ResourceRef: "arn:aws:s3:::bucket",
				Platform:    "aws",
				Match: &types.Match{
					RuleID:           "np.aws.1",
					ValidationResult: tc.validation,
				},
			}
			risk, err := result.ToRisk()
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, risk.Status)
			assert.Contains(t, []string{"TI", "TL", "TM", "TH", "TC"}, risk.Status)
		})
	}
}

func TestToRisk_TargetNameWithFindingID(t *testing.T) {
	result := SecretScanResult{
		ResourceRef: "arn:aws:lambda:us-east-1:123:function:demo",
		Platform:    "aws",
		Match: &types.Match{
			RuleID:    "np.aws.1",
			FindingID: "abc123def456",
		},
	}
	risk, err := result.ToRisk()
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123:function:demo:abc123de", risk.TargetName,
		"FindingID prefix (8 chars) should be appended to ResourceRef")
}

func TestToRisk_TargetNameWithoutFindingID(t *testing.T) {
	result := SecretScanResult{
		ResourceRef: "i-08da3f571f1346176",
		Platform:    "aws",
		Match: &types.Match{
			RuleID: "np.aws.1",
		},
	}
	risk, err := result.ToRisk()
	require.NoError(t, err)
	assert.Equal(t, "i-08da3f571f1346176", risk.TargetName,
		"bare ResourceRef should be used when FindingID is empty")
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
