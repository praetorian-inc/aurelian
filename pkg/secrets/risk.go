package secrets

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/titus/pkg/types"
)

// NewSecretRisk constructs an AurelianRisk from a scan result and pre-marshalled proof bytes.
// The platform prefix (e.g. "aws", "gcp", "azure") is used to form the risk name.
func NewSecretRisk(result SecretScanResult, platform string, proofBytes []byte) output.AurelianRisk {
	impactedID := result.ResourceRef
	if result.Match.FindingID != "" {
		findingPrefix := result.Match.FindingID
		if len(findingPrefix) > 8 {
			findingPrefix = findingPrefix[:8]
		}
		impactedID = fmt.Sprintf("%s:%s", result.ResourceRef, findingPrefix)
	}

	return output.AurelianRisk{
		Name:               fmt.Sprintf("%s-secret-%s", platform, ExtractRuleShortName(result.Match.RuleID)),
		Severity:           RiskSeverityFromMatch(result.Match),
		ImpactedResourceID: impactedID,
		DeduplicationID:    result.Match.FindingID,
		Context:            proofBytes,
	}
}

// ExtractRuleShortName extracts the short rule identifier from a Titus rule ID.
// For IDs like "np.aws.1", returns "aws". For single-segment IDs, returns the
// full ID lowercased.
func ExtractRuleShortName(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	if len(parts) >= 2 {
		return parts[1]
	}
	return strings.ToLower(ruleID)
}

// RiskSeverityFromMatch returns the risk severity based on the match's validation result.
func RiskSeverityFromMatch(match *types.Match) output.RiskSeverity {
	if match.ValidationResult != nil && match.ValidationResult.Status == types.StatusValid {
		return output.RiskSeverityHigh
	}
	return output.RiskSeverityMedium
}
