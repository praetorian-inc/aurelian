package recon

import (
	"testing"

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
		got := extractRuleShortName(tc.ruleID)
		if got != tc.want {
			t.Errorf("extractRuleShortName(%q) = %q, want %q", tc.ruleID, got, tc.want)
		}
	}
}

func TestFormatSecretRiskName(t *testing.T) {
	got := formatSecretRiskName("np.gcp.3")
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
	got := riskSeverityFromMatch(m)
	if got != "high" {
		t.Errorf("severity = %q, want %q", got, "high")
	}
}

func TestRiskSeverityFromMatch_Unvalidated(t *testing.T) {
	m := &types.Match{}
	got := riskSeverityFromMatch(m)
	if got != "medium" {
		t.Errorf("severity = %q, want %q", got, "medium")
	}
}
