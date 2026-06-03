package plugin

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRisk(t *testing.T) capmodel.Risk {
	t.Helper()
	proofBytes, err := json.Marshal(capmodel.Proof{
		Format:   "v1.0.0",
		Sections: []capmodel.ProofSection{{Title: "Summary"}},
	})
	require.NoError(t, err)
	return capmodel.Risk{
		TargetName: "example.cloudfront.net",
		Name:       "CloudFront S3 Origin Takeover",
		Status:     "TM",
		Proof:      proofBytes,
	}
}

func TestExtractProofSidecar_DecodesProof(t *testing.T) {
	risk := newTestRisk(t)

	entries := ExtractProofSidecar([]model.AurelianModel{risk})

	require.Len(t, entries, 1)
	assert.Equal(t, "example.cloudfront.net", entries[0].TargetName)
	assert.Equal(t, "CloudFront S3 Origin Takeover", entries[0].Name)
	assert.Equal(t, "TM", entries[0].Status)

	out, err := json.MarshalIndent(entries, "", "  ")
	require.NoError(t, err)
	rendered := string(out)

	// Proof must be decoded JSON, not a base64 blob.
	assert.Contains(t, rendered, `"format": "v1.0.0"`)
	assert.Contains(t, rendered, `"title": "Summary"`)
	assert.Contains(t, rendered, `"proof": {`)
	assert.NotContains(t, rendered, `"proof": "ey`)
}

func TestExtractProofSidecar_PointerRisk(t *testing.T) {
	risk := newTestRisk(t)

	entries := ExtractProofSidecar([]model.AurelianModel{&risk})

	require.Len(t, entries, 1)
	assert.Equal(t, "example.cloudfront.net", entries[0].TargetName)
}

func TestExtractProofSidecar_NonRiskIgnored(t *testing.T) {
	type dummy struct{ Foo string }

	entries := ExtractProofSidecar([]model.AurelianModel{dummy{Foo: "bar"}})

	assert.Empty(t, entries)
}

func TestExtractProofSidecar_EmptyProofSkipped(t *testing.T) {
	risk := newTestRisk(t)
	risk.Proof = nil

	entries := ExtractProofSidecar([]model.AurelianModel{risk})

	assert.Empty(t, entries)
}

func TestExtractProofSidecar_InvalidJSONProofSkipped(t *testing.T) {
	risk := newTestRisk(t)
	risk.Proof = []byte("not json")

	entries := ExtractProofSidecar([]model.AurelianModel{risk})

	assert.Empty(t, entries)
}

func TestExtractProofSidecar_EmptyResults(t *testing.T) {
	entries := ExtractProofSidecar(nil)

	assert.Nil(t, entries)
	assert.False(t, len(entries) > 0)
}

func TestWriteProofSidecar_ValidJSON(t *testing.T) {
	entries := ExtractProofSidecar([]model.AurelianModel{newTestRisk(t)})
	require.Len(t, entries, 1)

	var buf bytes.Buffer
	require.NoError(t, WriteProofSidecar(&buf, entries))

	var decoded []ProofSidecarEntry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	require.Len(t, decoded, 1)
	assert.Equal(t, "example.cloudfront.net", decoded[0].TargetName)
	assert.True(t, json.Valid(decoded[0].Proof))
}

func TestProofSidecarPath(t *testing.T) {
	assert.Equal(t,
		"aurelian-output/cloudfront-s3-takeover-20260604-024413.proof.json",
		ProofSidecarPath("aurelian-output/cloudfront-s3-takeover-20260604-024413.json"))

	// No .json suffix: append.
	assert.Equal(t, "results.proof.json", ProofSidecarPath("results"))
	assert.Equal(t, "results.txt.proof.json", ProofSidecarPath("results.txt"))
}

func TestWriteProofSidecar_NoBase64Proof(t *testing.T) {
	entries := ExtractProofSidecar([]model.AurelianModel{newTestRisk(t)})

	var buf bytes.Buffer
	require.NoError(t, WriteProofSidecar(&buf, entries))

	rendered := buf.String()
	assert.Contains(t, rendered, `"proof": {`)
	assert.False(t, strings.Contains(rendered, `"proof": "ey`))
}
