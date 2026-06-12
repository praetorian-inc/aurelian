package secrets

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/praetorian-inc/titus/pkg/types"
)

// proofVersion is the schema version of the secrets proof carried in
// capmodel.Risk.Proof. Bump when the SecretProof layout changes.
const proofVersion = "v1.0.0"

// SecretProof is the typed, versioned representation of Guard's secrets proof.
// JSON tags reproduce the legacy proof keys exactly so Guard remains a thin
// pass-through; Guard derives dedup identity from finding_id.
type SecretProof struct {
	Version     string        `json:"version"`
	FindingID   string        `json:"finding_id"`
	RuleName    string        `json:"rule_name"`
	RuleTextID  string        `json:"rule_text_id"`
	ResourceRef string        `json:"resource_ref"`
	NumMatches  int           `json:"num_matches"`
	Matches     []SecretMatch `json:"matches"`
	Validation  *Validation   `json:"validation,omitempty"`
}

type SecretMatch struct {
	Provenance []Provenance `json:"provenance"`
	Snippet    Snippet      `json:"snippet"`
	Location   Location     `json:"location"`
}

type Provenance struct {
	Kind         string `json:"kind"`
	Platform     string `json:"platform"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Region       string `json:"region"`
	AccountID    string `json:"account_id"`
	Subresource  string `json:"subresource"`
}

type Snippet struct {
	Before   string `json:"before"`
	Matching string `json:"matching"`
	After    string `json:"after"`
}

type Location struct {
	OffsetSpan OffsetSpan `json:"offset_span"`
	SourceSpan SourceSpan `json:"source_span"`
}

type OffsetSpan struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

type SourceSpan struct {
	Start SourcePoint `json:"start"`
	End   SourcePoint `json:"end"`
}

type SourcePoint struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type Validation struct {
	Status     string  `json:"status"`
	Confidence float64 `json:"confidence"`
	Message    string  `json:"message"`
}

// proofData builds the typed secrets proof from the scan result, preserving the
// exact JSON shape Guard expects.
func (r SecretScanResult) proofData() SecretProof {
	proof := SecretProof{
		Version:     proofVersion,
		FindingID:   r.Match.FindingID,
		RuleName:    r.Match.RuleName,
		RuleTextID:  r.Match.RuleID,
		ResourceRef: r.ResourceRef,
		NumMatches:  1,
		Matches: []SecretMatch{
			{
				Provenance: []Provenance{
					{
						Kind:         "cloud",
						Platform:     r.Platform,
						ResourceID:   r.ResourceRef,
						ResourceType: r.ResourceType,
						Region:       r.Region,
						AccountID:    r.AccountID,
						Subresource:  r.Label,
					},
				},
				Snippet: Snippet{
					Before:   string(r.Match.Snippet.Before),
					Matching: string(r.Match.Snippet.Matching),
					After:    string(r.Match.Snippet.After),
				},
				Location: Location{
					OffsetSpan: OffsetSpan{
						Start: r.Match.Location.Offset.Start,
						End:   r.Match.Location.Offset.End,
					},
					SourceSpan: SourceSpan{
						Start: SourcePoint{
							Line:   r.Match.Location.Source.Start.Line,
							Column: r.Match.Location.Source.Start.Column,
						},
						End: SourcePoint{
							Line:   r.Match.Location.Source.End.Line,
							Column: r.Match.Location.Source.End.Column,
						},
					},
				},
			},
		},
	}

	if r.Match.ValidationResult != nil {
		proof.Validation = &Validation{
			Status:     string(r.Match.ValidationResult.Status),
			Confidence: r.Match.ValidationResult.Confidence,
			Message:    r.Match.ValidationResult.Message,
		}
	}

	return proof
}

// ToRisk converts a scan result into a platform capmodel.Risk carrying the
// marshalled secrets proof.
func (r SecretScanResult) ToRisk() (capmodel.Risk, error) {
	impactedID := r.ResourceRef
	if r.Match.FindingID != "" {
		findingPrefix := r.Match.FindingID
		if len(findingPrefix) > 8 {
			findingPrefix = findingPrefix[:8]
		}
		impactedID = fmt.Sprintf("%s:%s", r.ResourceRef, findingPrefix)
	}

	proof, err := json.Marshal(r.proofData())
	if err != nil {
		return capmodel.Risk{}, fmt.Errorf("marshalling proof: %w", err)
	}

	return capmodel.Risk{
		Name:       fmt.Sprintf("%s-secret-%s", r.Platform, ExtractRuleShortName(r.Match.RuleID)),
		TargetName: impactedID,
		Status:     severityToStatus(RiskSeverityFromMatch(r.Match)),
		Source:     "aurelian",
		Proof:      proof,
		// TODO(LAB-3740): populate a typed capmodel asset for the impacted resource once
		// Aurelian emits the SDK `_type` envelope and Guard's ingest consumes Risk.Target.
		// Inert until then — Guard's convertRisk falls back to a bare Asset without a
		// `_type` discriminator.
		Target: nil,
	}, nil
}

// RiskFromScanResult is a pipeline-compatible function that converts
// SecretScanResult to capmodel.Risk and sends it to the output pipeline.
func RiskFromScanResult(result SecretScanResult, out *pipeline.P[model.AurelianModel]) error {
	risk, err := result.ToRisk()
	if err != nil {
		slog.Warn("failed to build risk", "resource", result.ResourceRef, "error", err)
		return nil
	}
	out.Send(risk)
	return nil
}

// severityToStatus maps a risk severity to a Chariot triage status code.
func severityToStatus(sev output.RiskSeverity) string {
	switch output.NormalizeSeverity(sev) {
	case output.RiskSeverityCritical:
		return "TC"
	case output.RiskSeverityHigh:
		return "TH"
	case output.RiskSeverityMedium:
		return "TM"
	case output.RiskSeverityLow:
		return "TL"
	default:
		return "TI"
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
