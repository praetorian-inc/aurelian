package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

// Formatter handles output formatting for module results
type Formatter interface {
	Format(results []model.AurelianModel) error
}

// JSONFormatter outputs results as JSON
type JSONFormatter struct {
	Writer io.Writer
	Pretty bool
}

// Format implements the Formatter interface for JSON output
func (f *JSONFormatter) Format(results []model.AurelianModel) error {
	encoder := json.NewEncoder(f.Writer)
	if f.Pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(results)
}

// ConsoleFormatter outputs results to console in a human-readable format
type ConsoleFormatter struct {
	Writer io.Writer
}

// Format implements the Formatter interface for console output
func (f *ConsoleFormatter) Format(results []model.AurelianModel) error {
	for _, r := range results {
		_, _ = fmt.Fprintf(f.Writer, "%+v\n", r)
	}
	return nil
}

// ProofSidecarEntry is one decoded risk proof for the human-readable sidecar
// file. The canonical results file encodes capmodel.Risk.Proof ([]byte) as a
// base64 string; here Proof is json.RawMessage so the encoder emits the decoded
// proof object verbatim.
type ProofSidecarEntry struct {
	TargetName string          `json:"target_name"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	Proof      json.RawMessage `json:"proof"`
}

// ExtractProofSidecar returns one entry per emitted capmodel.Risk that carries a
// non-empty, valid-JSON proof. Non-risk results and risks without a usable proof
// are skipped. Returns nil when no entry qualifies.
func ExtractProofSidecar(results []model.AurelianModel) []ProofSidecarEntry {
	var entries []ProofSidecarEntry
	for _, r := range results {
		var risk capmodel.Risk
		switch v := r.(type) {
		case capmodel.Risk:
			risk = v
		case *capmodel.Risk:
			risk = *v
		default:
			continue
		}

		if len(risk.Proof) == 0 || !json.Valid(risk.Proof) {
			continue
		}

		entries = append(entries, ProofSidecarEntry{
			TargetName: risk.TargetName,
			Name:       risk.Name,
			Status:     risk.Status,
			Proof:      json.RawMessage(risk.Proof),
		})
	}
	return entries
}

// WriteProofSidecar pretty-encodes the sidecar entries (2-space indent) to w.
func WriteProofSidecar(w io.Writer, entries []ProofSidecarEntry) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(entries)
}

// ProofSidecarPath derives the sidecar path from the main output path by
// replacing a trailing ".json" with ".proof.json". If the path does not end in
// ".json", ".proof.json" is appended.
func ProofSidecarPath(outputPath string) string {
	if base, ok := strings.CutSuffix(outputPath, ".json"); ok {
		return base + ".proof.json"
	}
	return outputPath + ".proof.json"
}
