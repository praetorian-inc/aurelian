package secrets

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/titus/pkg/types"
)

// SecretScanner provides an object-oriented interface for scanning content for secrets.
type SecretScanner struct {
	ps *persistentScanner
}

// SecretScanResult represents a secret detection result emitted by the scanner.
type SecretScanResult struct {
	ResourceRef string       `json:"resource_ref"`
	Label       string       `json:"label"`
	Match       *types.Match `json:"match"`
}

// Start creates a new persistent scanner and stores it as a field.
// The dbPath parameter specifies the SQLite database path; if empty, a default is used.
func (s *SecretScanner) Start(dbPath string) error {
	ps, err := newPersistentScanner(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	s.ps = ps
	slog.Info("secret scanner started", "db", ps.dbPath)
	return nil
}

// Close closes the underlying persistent scanner and releases resources.
func (s *SecretScanner) Close() error {
	if s.ps == nil {
		return nil
	}
	err := s.ps.close()
	s.ps = nil
	return err
}

// DBPath returns the path to the SQLite database, or empty string if not started.
func (s *SecretScanner) DBPath() string {
	if s.ps == nil {
		return ""
	}
	return s.ps.dbPath
}

// Scan is a pipeline-compatible method that scans a ScanInput for secrets
// and sends SecretScanResult values to the output pipeline.
func (s *SecretScanner) Scan(input output.ScanInput, out *pipeline.P[SecretScanResult]) error {
	blobID := types.ComputeBlobID(input.Content)
	provenance := types.FileProvenance{FilePath: input.Label}

	matches, err := s.ps.scanContent(input.Content, blobID, provenance)
	if err != nil {
		slog.Warn("failed to scan content for secrets", "resource", input.ResourceID, "label", input.Label, "error", err)
		return nil
	}

	for _, match := range matches {
		out.Send(toScanResult(input, match))
	}
	return nil
}

func toScanResult(input output.ScanInput, match *types.Match) SecretScanResult {
	return SecretScanResult{
		ResourceRef: input.ResourceID,
		Label:       input.Label,
		Match:       match,
	}
}
