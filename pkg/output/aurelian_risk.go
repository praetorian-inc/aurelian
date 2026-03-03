package output

import (
	"encoding/json"

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

type AurelianRisk struct {
	model.BaseAurelianModel
	Name        string          `json:"name"`
	Severity    RiskSeverity    `json:"severity"`
	ImpactedARN string          `json:"impacted_arn,omitempty"`
	Context     json.RawMessage `json:"context,omitempty"`
}
