package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected RiskSeverity
	}{
		{"info", RiskSeverityInfo},
		{"low", RiskSeverityLow},
		{"medium", RiskSeverityMedium},
		{"high", RiskSeverityHigh},
		{"critical", RiskSeverityCritical},
		{"Info", RiskSeverityInfo},
		{"LOW", RiskSeverityLow},
		{"Medium", RiskSeverityMedium},
		{"HIGH", RiskSeverityHigh},
		{"Critical", RiskSeverityCritical},
		{"unknown", RiskSeverityMedium},
		{"", RiskSeverityMedium},
		{"severe", RiskSeverityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, NormalizeSeverity(tt.input))
		})
	}
}
