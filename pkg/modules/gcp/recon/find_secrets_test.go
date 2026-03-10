package recon

import (
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestExtractRuleShortName(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		{"np.aws.1", "aws"},
		{"np.gcp.3", "gcp"},
		{"custom", "custom"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, secrets.ExtractRuleShortName(tc.ruleID))
	}
}

func TestFormatSecretRiskName(t *testing.T) {
	got := fmt.Sprintf("gcp-secret-%s", secrets.ExtractRuleShortName("np.gcp.3"))
	assert.Equal(t, "gcp-secret-gcp", got)
}

func TestRiskSeverityFromMatch_Validated(t *testing.T) {
	m := &types.Match{
		ValidationResult: &types.ValidationResult{
			Status: types.StatusValid,
		},
	}
	assert.Equal(t, output.RiskSeverityHigh, secrets.RiskSeverityFromMatch(m))
}

func TestRiskSeverityFromMatch_Unvalidated(t *testing.T) {
	m := &types.Match{}
	assert.Equal(t, output.RiskSeverityMedium, secrets.RiskSeverityFromMatch(m))
}
