package secrets

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A versioned SSM document ScanInput must yield a risk whose impacted resource
// and proof provenance both name the version holding the secret — on the
// immediate path and on the drain-recovery path that rebuilds the input from
// stored provenance.
func TestToRisk_SSMDocumentVersionCarriedIntoRisk(t *testing.T) {
	const docARN = "arn:aws:ssm:us-east-2:123456789012:document/deploy"
	input := output.ScanInput{
		Platform:     "aws",
		ResourceID:   docARN + ":4",
		ResourceType: "AWS::SSM::Document",
		Region:       "us-east-2",
		AccountID:    "123456789012",
		Label:        "Document version 4",
	}
	match := &types.Match{
		FindingID: "abcdef0123456789",
		RuleID:    "np.aws.6",
		RuleName:  "AWS API Credentials",
		Snippet:   types.Snippet{Matching: []byte("AKIAIOSFODNN7EXAMPLE")},
	}

	paths := map[string]output.ScanInput{
		"immediate":          input,
		"provenance-recover": scanInputFromProvenance(provenanceFromScanInput(input)),
	}
	for name, in := range paths {
		t.Run(name, func(t *testing.T) {
			risk, err := toScanResult(in, match).ToRisk()
			require.NoError(t, err)

			assert.True(t, strings.HasPrefix(risk.ImpactedResourceID, docARN+":4:"),
				"ImpactedResourceID %q must start with the versioned ARN", risk.ImpactedResourceID)
			assert.Equal(t, docARN+":4:abcdef01", risk.ImpactedResourceID)

			var proof struct {
				ResourceRef string `json:"resource_ref"`
				Matches     []struct {
					Provenance []map[string]any `json:"provenance"`
				} `json:"matches"`
			}
			require.NoError(t, json.Unmarshal(risk.Context, &proof))
			assert.Equal(t, docARN+":4", proof.ResourceRef)
			require.Len(t, proof.Matches, 1)
			require.Len(t, proof.Matches[0].Provenance, 1)
			prov := proof.Matches[0].Provenance[0]
			assert.Equal(t, "Document version 4", prov["subresource"])
			assert.Equal(t, docARN+":4", prov["resource_id"])
			assert.Equal(t, "AWS::SSM::Document", prov["resource_type"])
		})
	}
}
