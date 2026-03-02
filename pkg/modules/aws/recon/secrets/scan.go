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

// ScanForSecrets returns a pipeline-compatible function that scans each ScanInput
// for secrets using the provided Scanner and emits SecretFinding results.
func ScanForSecrets(s Scanner) func(ScanInput, *pipeline.P[output.SecretFinding]) error {
	return func(input ScanInput, out *pipeline.P[output.SecretFinding]) error {
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
			if match.ValidationResult != nil && match.ValidationResult.Status == types.StatusValid {
				confidence = "high"
			}

			finding := output.SecretFinding{
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
