package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    RiskSeverity
		expected RiskSeverity
	}{
		{"Critical", RiskSeverityCritical},
		{"critical", RiskSeverityCritical},
		{"High", RiskSeverityHigh},
		{"high", RiskSeverityHigh},
		{"Medium", RiskSeverityMedium},
		{"medium", RiskSeverityMedium},
		{"Low", RiskSeverityLow},
		{"low", RiskSeverityLow},
		{"Info", RiskSeverityInfo},
		{"unknown", RiskSeverityInfo},
		{"", RiskSeverityInfo},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			assert.Equal(t, tt.expected, NormalizeSeverity(tt.input))
		})
	}
}
