package secrets

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/titus/pkg/types"
)

// proofData constructs proof JSON matching Guard's secrets proof format.
func (r SecretScanResult) proofData() map[string]any {
	proof := map[string]any{
		"finding_id":   r.Match.FindingID,
		"rule_name":    r.Match.RuleName,
		"rule_text_id": r.Match.RuleID,
		"resource_ref": r.ResourceRef,
		"num_matches":  1,
		"matches": []map[string]any{
			{
				"provenance": []map[string]any{
					{
						"kind":          "cloud",
						"platform":      r.Platform,
						"resource_id":   r.ResourceRef,
						"resource_type": r.ResourceType,
						"region":        r.Region,
						"account_id":    r.AccountID,
						"subresource":   r.Label,
					},
				},
				"snippet": map[string]string{
					"before":   string(r.Match.Snippet.Before),
					"matching": string(r.Match.Snippet.Matching),
					"after":    string(r.Match.Snippet.After),
				},
				"location": map[string]any{
					"offset_span": map[string]any{
						"start": r.Match.Location.Offset.Start,
						"end":   r.Match.Location.Offset.End,
					},
					"source_span": map[string]any{
						"start": map[string]any{
							"line":   r.Match.Location.Source.Start.Line,
							"column": r.Match.Location.Source.Start.Column,
						},
						"end": map[string]any{
							"line":   r.Match.Location.Source.End.Line,
							"column": r.Match.Location.Source.End.Column,
						},
					},
				},
			},
		},
	}

	if r.Match.ValidationResult != nil {
		proof["validation"] = map[string]any{
			"status":     string(r.Match.ValidationResult.Status),
			"confidence": r.Match.ValidationResult.Confidence,
			"message":    r.Match.ValidationResult.Message,
		}
	}

	return proof
}

// ToRisk converts a scan result into an AurelianRisk with marshalled proof.
func (r SecretScanResult) ToRisk() (output.AurelianRisk, error) {
	proofBytes, err := json.Marshal(r.proofData())
	if err != nil {
		return output.AurelianRisk{}, fmt.Errorf("marshalling proof: %w", err)
	}
	return newSecretRisk(r, proofBytes), nil
}

// RiskFromScanResult is a pipeline-compatible function that converts
// SecretScanResult to AurelianRisk and sends it to the output pipeline.
func RiskFromScanResult(result SecretScanResult, out *pipeline.P[model.AurelianModel]) error {
	risk, err := result.ToRisk()
	if err != nil {
		slog.Warn("failed to build risk", "resource", result.ResourceRef, "error", err)
		return nil
	}
	out.Send(risk)
	return nil
}

// newSecretRisk constructs an AurelianRisk from a scan result and pre-marshalled proof bytes.
func newSecretRisk(result SecretScanResult, proofBytes []byte) output.AurelianRisk {
	impactedID := result.ResourceRef
	if result.Match.FindingID != "" {
		findingPrefix := result.Match.FindingID
		if len(findingPrefix) > 8 {
			findingPrefix = findingPrefix[:8]
		}
		impactedID = fmt.Sprintf("%s:%s", result.ResourceRef, findingPrefix)
	}

	return output.AurelianRisk{
		Name:               fmt.Sprintf("%s-secret-%s", result.Platform, ExtractRuleShortName(result.Match.RuleID)),
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
