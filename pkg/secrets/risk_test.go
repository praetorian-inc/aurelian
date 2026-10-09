package secrets

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToRiskSurfacesLastModified(t *testing.T) {
	// #258 added LastModified to AWSResource but used it only as an input-side
	// skip filter, so no finding recorded WHICH revision of a resource produced
	// it. A caller advancing a --modified-since checkpoint had nothing to
	// advance it to but wall-clock time, leaving a gap for resources modified
	// mid-scan.
	modified := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	result := SecretScanResult{
		ResourceRef:  "arn:aws:ecr:us-east-2:123456789012:repository/app",
		ResourceType: "AWS::ECR::Repository",
		Region:       "us-east-2",
		AccountID:    "123456789012",
		Platform:     "aws",
		Label:        "app:v3:layer0/app/config.env",
		LastModified: &modified,
		Match: &types.Match{
			RuleID:    "np.aws.1",
			RuleName:  "AWS API Key",
			FindingID: "abcdef1234567890",
		},
	}

	risk, err := result.ToRisk()
	require.NoError(t, err)

	var proof struct {
		Matches []struct {
			Provenance []struct {
				LastModified string `json:"last_modified"`
			} `json:"provenance"`
		} `json:"matches"`
	}
	require.NoError(t, json.Unmarshal(risk.Context, &proof))
	require.Len(t, proof.Matches, 1)
	require.Len(t, proof.Matches[0].Provenance, 1)
	assert.Equal(t, modified.Format(time.RFC3339Nano), proof.Matches[0].Provenance[0].LastModified)
}

func TestToRiskOmitsUnknownLastModified(t *testing.T) {
	// An enumerator with no authoritative modification time must yield null, not
	// the epoch: "unknown" and "modified in 1970" mean different things to a
	// consumer deciding whether to rescan.
	result := SecretScanResult{
		ResourceRef: "arn:aws:lambda:us-east-2:123456789012:function:f",
		Platform:    "aws",
		Match:       &types.Match{RuleID: "np.aws.1", FindingID: "abc"},
	}

	risk, err := result.ToRisk()
	require.NoError(t, err)

	var proof map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &proof))
	matches := proof["matches"].([]any)
	provenance := matches[0].(map[string]any)["provenance"].([]any)
	entry := provenance[0].(map[string]any)

	value, present := entry["last_modified"]
	assert.True(t, present, "the key should be present so consumers can distinguish absent from omitted")
	assert.Nil(t, value, "an unknown modification time must be null, not a zero timestamp")
}

func TestProvenanceRoundTripPreservesLastModified(t *testing.T) {
	// Matches recovered from Titus' regexp-timeout queue are rebuilt from the
	// stored provenance, so anything the round trip drops is lost for exactly
	// those findings.
	modified := time.Date(2026, time.August, 24, 12, 0, 0, 123456789, time.UTC)
	in := output.ScanInput{
		Platform:     "aws",
		ResourceID:   "arn:aws:ecr:us-east-2:123456789012:repository/app",
		ResourceType: "AWS::ECR::Repository",
		Region:       "us-east-2",
		AccountID:    "123456789012",
		Label:        "app:v3:layer0/app/config.env",
		LastModified: &modified,
	}

	out := scanInputFromProvenance(provenanceFromScanInput(in))

	require.NotNil(t, out.LastModified)
	assert.True(t, out.LastModified.Equal(modified))
	assert.Equal(t, in.ResourceID, out.ResourceID)
	assert.Equal(t, in.Label, out.Label)
}

func TestProvenanceRoundTripHandlesUnknownLastModified(t *testing.T) {
	out := scanInputFromProvenance(provenanceFromScanInput(output.ScanInput{Platform: "aws"}))
	assert.Nil(t, out.LastModified, "an absent time must round-trip to nil, not a zero time")
}

func TestScanInputFromAWSResourceCarriesLastModified(t *testing.T) {
	// Every AWS extractor builds its ScanInput through this helper, so mapping it
	// here is what surfaces the four timestamp-bearing enumerators #258 added.
	modified := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	in := output.ScanInputFromAWSResource(output.AWSResource{
		ARN:          "arn:aws:lambda:us-east-2:123456789012:function:f",
		ResourceType: "AWS::Lambda::Function",
		LastModified: &modified,
	}, "handler.py", []byte("x"))

	require.NotNil(t, in.LastModified)
	assert.Equal(t, modified, *in.LastModified)
}
