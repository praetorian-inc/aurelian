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

// NormalizeSeverity maps a severity string (case-insensitive) to a canonical RiskSeverity constant.
func NormalizeSeverity(s RiskSeverity) RiskSeverity {
	switch RiskSeverity(strings.ToLower(string(s))) {
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
	Name               string          `json:"name"`
	Severity           RiskSeverity    `json:"severity"`
	ImpactedResourceID string          `json:"impacted_resource_id,omitempty"`
	DeduplicationID    string          `json:"deduplication_id,omitempty"`
	Context            json.RawMessage `json:"context,omitempty"`
}
