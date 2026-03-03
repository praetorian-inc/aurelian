package secrets

import (
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Scanner abstracts the Titus scanning interface for testability.
type Scanner interface {
	ScanContent(content []byte, blobID types.BlobID, provenance types.Provenance) ([]*types.Match, error)
}

// SecretScanResult represents a secret detection result emitted by the scanner stage.
type SecretScanResult struct {
	ResourceRef string `json:"resource_ref"`
	RuleName    string `json:"rule_name"`
	RuleTextID  string `json:"rule_text_id"`
	Match       string `json:"match,omitempty"`
	FilePath    string `json:"file_path,omitempty"`
	LineNumber  int    `json:"line_number,omitempty"`
	Confidence  string `json:"confidence"`
}

// ScanForSecrets returns a pipeline-compatible function that scans each output.ScanInput
// for secrets using the provided Scanner and emits SecretScanResult values.
func ScanForSecrets(s Scanner) func(output.ScanInput, *pipeline.P[SecretScanResult]) error {
	return func(input output.ScanInput, out *pipeline.P[SecretScanResult]) error {
		blobID := types.ComputeBlobID(input.Content)

		provenance := types.FileProvenance{
			FilePath: input.Label,
		}

		matches, err := s.ScanContent(input.Content, blobID, provenance)
		if err != nil {
			return nil // skip content that fails to scan
		}

		for _, match := range matches {
			confidence := "medium"
			hasValidValidationResult := match.ValidationResult != nil && match.ValidationResult.Status == types.StatusValid
			if hasValidValidationResult {
				confidence = "high"
			}

			finding := SecretScanResult{
				ResourceRef: input.ResourceID,
				RuleName:    match.RuleName,
				RuleTextID:  match.RuleID,
				Match:       string(match.Snippet.Matching),
				FilePath:    input.Label,
				LineNumber:  match.Location.Source.Start.Line,
				Confidence:  confidence,
			}

			out.Send(finding)
		}

		return nil
	}
}
