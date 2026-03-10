package recon

import (
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
	"github.com/praetorian-inc/titus/pkg/types"
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
		got := secrets.ExtractRuleShortName(tc.ruleID)
		if got != tc.want {
			t.Errorf("ExtractRuleShortName(%q) = %q, want %q", tc.ruleID, got, tc.want)
		}
	}
}

func TestFormatSecretRiskName(t *testing.T) {
	got := fmt.Sprintf("gcp-secret-%s", secrets.ExtractRuleShortName("np.gcp.3"))
	if got != "gcp-secret-gcp" {
		t.Errorf("formatSecretRiskName = %q, want %q", got, "gcp-secret-gcp")
	}
}

func TestRiskSeverityFromMatch_Validated(t *testing.T) {
	m := &types.Match{
		ValidationResult: &types.ValidationResult{
			Status: types.StatusValid,
		},
	}
	got := secrets.RiskSeverityFromMatch(m)
	if got != output.RiskSeverityHigh {
		t.Errorf("severity = %q, want %q", got, output.RiskSeverityHigh)
	}
}

func TestRiskSeverityFromMatch_Unvalidated(t *testing.T) {
	m := &types.Match{}
	got := secrets.RiskSeverityFromMatch(m)
	if got != output.RiskSeverityMedium {
		t.Errorf("severity = %q, want %q", got, output.RiskSeverityMedium)
	}
}
