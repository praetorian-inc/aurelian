package output

import "strings"

// NormalizeSeverity maps a severity string (case-insensitive) to a normalized RiskSeverity.
// Unknown values default to RiskSeverityMedium.
func NormalizeSeverity(s string) RiskSeverity {
	switch strings.ToLower(s) {
	case "info":
		return RiskSeverityInfo
	case "low":
		return RiskSeverityLow
	case "medium":
		return RiskSeverityMedium
	case "high":
		return RiskSeverityHigh
	case "critical":
		return RiskSeverityCritical
	default:
		return RiskSeverityMedium
	}
}
