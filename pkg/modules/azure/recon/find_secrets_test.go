package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestFormatSecretRiskName(t *testing.T) {
	m := &AzureFindSecretsModule{}
	tests := []struct {
		ruleID   string
		expected string
	}{
		// Standard case: "prefix.RuleName" → "azure-secret-RuleName"
		{"aws.AccessKey", "azure-secret-AccessKey"},
		// No dots: whole ID lowercased
		{"genericcredential", "azure-secret-genericcredential"},
		// Multiple dots: second segment used (parts[1])
		{"provider.RuleName.extra", "azure-secret-RuleName"},
		// Empty string
		{"", "azure-secret-"},
		// Single dot with empty second segment
		{"prefix.", "azure-secret-"},
	}
	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := m.formatSecretRiskName(tt.ruleID)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestRiskSeverityFromMatch_ValidatedHigh(t *testing.T) {
	m := &AzureFindSecretsModule{}
	match := &types.Match{
		ValidationResult: &types.ValidationResult{
			Status: types.StatusValid,
		},
	}
	assert.Equal(t, output.RiskSeverityHigh, m.riskSeverityFromMatch(match))
}

func TestRiskSeverityFromMatch_UnvalidatedMedium(t *testing.T) {
	m := &AzureFindSecretsModule{}
	// nil ValidationResult
	assert.Equal(t, output.RiskSeverityMedium, m.riskSeverityFromMatch(&types.Match{}))
}

func TestRiskSeverityFromMatch_InvalidStatusMedium(t *testing.T) {
	m := &AzureFindSecretsModule{}
	match := &types.Match{
		ValidationResult: &types.ValidationResult{
			Status: types.StatusInvalid,
		},
	}
	assert.Equal(t, output.RiskSeverityMedium, m.riskSeverityFromMatch(match))
}
