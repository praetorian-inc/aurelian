package output

import (
	"encoding/json"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
)

type RiskSeverity string

const (
	RiskSeverityInfo     RiskSeverity = "info"
	RiskSeverityLow      RiskSeverity = "low"
	RiskSeverityMedium   RiskSeverity = "medium"
	RiskSeverityHigh     RiskSeverity = "high"
	RiskSeverityCritical RiskSeverity = "critical"
)

// NormalizeSeverity converts a severity string to its canonical lowercase form.
func NormalizeSeverity(s string) string {
	return string(mapToRiskSeverity(s))
}

func mapToRiskSeverity(s string) RiskSeverity {
	switch RiskSeverity(strings.ToLower(s)) {
	case RiskSeverityCritical:
		return RiskSeverityCritical
	case RiskSeverityHigh:
		return RiskSeverityHigh
	case RiskSeverityMedium:
		return RiskSeverityMedium
	case RiskSeverityLow:
		return RiskSeverityLow
	default:
		return RiskSeverityInfo
	}
}

type AurelianRisk struct {
	model.BaseAurelianModel
	Name        string          `json:"name"`
	Severity    RiskSeverity    `json:"severity"`
	ImpactedARN string          `json:"impacted_arn,omitempty"`
	Context     json.RawMessage `json:"context,omitempty"`
}
