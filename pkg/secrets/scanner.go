package secrets

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
)

// SecretScanner provides an object-oriented interface for scanning content for secrets.
type SecretScanner struct {
	ps       *persistentScanner
	validate bool
	engine   *validator.Engine
}

// SecretScanResult represents a secret detection result emitted by the scanner.
type SecretScanResult struct {
	ResourceRef  string       `json:"resource_ref"`
	ResourceType string       `json:"resource_type"`
	Region       string       `json:"region"`
	AccountID    string       `json:"account_id"`
	Label        string       `json:"label"`
	Match        *types.Match `json:"match"`
}

// Start creates a new persistent scanner and stores it as a field.
func (s *SecretScanner) Start(cfg ScannerConfig) error {
	ps, err := newPersistentScanner(cfg.DBPath, cfg.DisabledTitusRules)
	if err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	s.ps = ps
	s.validate = cfg.Validate

	if cfg.Validate {
		s.engine = validator.NewDefaultEngine(4)
		slog.Info("secret scanner started with validation enabled", "db", ps.dbPath)
	} else {
		slog.Info("secret scanner started", "db", ps.dbPath)
	}

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
		if s.validate && s.engine != nil {
			s.validateMatch(match, input.ResourceID)
		}
		out.Send(toScanResult(input, match))
	}
	return nil
}

// validateMatch runs the validation engine against a match, populating its ValidationResult.
func (s *SecretScanner) validateMatch(match *types.Match, resourceID string) {
	result, err := s.engine.ValidateMatch(context.Background(), match)
	if err != nil {
		slog.Warn("failed to validate secret", "resource", resourceID, "rule", match.RuleID, "error", err)
		return
	}
	match.ValidationResult = result
}

func toScanResult(input output.ScanInput, match *types.Match) SecretScanResult {
	return SecretScanResult{
		ResourceRef:  input.ResourceID,
		ResourceType: input.ResourceType,
		Region:       input.Region,
		AccountID:    input.AccountID,
		Label:        input.Label,
		Match:        match,
	}
}
