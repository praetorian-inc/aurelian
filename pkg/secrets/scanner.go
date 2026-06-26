package secrets

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/titus/pkg/enum/ignore"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
)

// SecretScanner provides an object-oriented interface for scanning content for secrets.
type SecretScanner struct {
	ps         *persistentScanner
	validate   bool
	engine     *validator.Engine
	ignorePath func(string) bool
}

// SecretScanResult represents a secret detection result emitted by the scanner.
type SecretScanResult struct {
	ResourceRef  string       `json:"resource_ref"`
	ResourceType string       `json:"resource_type"`
	Region       string       `json:"region"`
	AccountID    string       `json:"account_id"`
	Platform     string       `json:"platform"`
	Label        string       `json:"label"`
	Match        *types.Match `json:"match"`
}

// Start creates a new persistent scanner and stores it as a field.
func (s *SecretScanner) Start(cfg ScannerConfig) error {
	ps, err := newPersistentScanner(cfg.DBPath, cfg.Ruleset, cfg.DisabledTitusRules)
	if err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}

	extraIgnoreLines := []string{}
	if cfg.IgnoreFile == "" {
		extraIgnoreLines = aurelianIgnoreExtraLines
	}

	ig, err := ignore.CompilePatterns(cfg.IgnoreFile, extraIgnoreLines...)
	if err != nil {
		_ = ps.close()
		return fmt.Errorf("failed to compile ignore patterns: %w", err)
	}

	s.ps = ps
	s.validate = cfg.Validate
	s.ignorePath = ig.MatchesPath

	if cfg.Validate {
		s.engine = validator.NewDefaultEngine(4)
		slog.Info("secret scanner started with validation enabled", "db", ps.dbPath)
	} else {
		slog.Info("secret scanner started", "db", ps.dbPath)
	}

	return nil
}

// DBPath returns the path to the SQLite database, or empty string if not started.
func (s *SecretScanner) DBPath() string {
	if s.ps == nil {
		return ""
	}
	return s.ps.dbPath
}

// ScanFlushAndClose runs ScanFlushAndClose over every input, flushes any timed-out retry
// matches into the same output pipeline, closes the scanner, then closes out.
// It is a drop-in replacement for `pipeline.Pipe(in, s.ScanFlushAndClose, out, opts...)`
// when the caller is done with the scanner. The drain runs only after every
// ScanFlushAndClose has completed, since the matcher's queue is shared across all scanned
// blobs. Closing the scanner before closing out ensures downstream consumers
// do not observe completion while the Titus database is still open.
func (s *SecretScanner) ScanFlushAndClose(in *pipeline.P[output.ScanInput], out *pipeline.P[SecretScanResult], opts ...*pipeline.PipeOpts) {
	if s.ps == nil {
		out.CloseWithError(fmt.Errorf("secret scanner not started or already closed"))
		return
	}

	scanned := pipeline.New[SecretScanResult]()
	pipeline.Pipe(in, s.Scan, scanned, opts...)

	go func() {
		var err error
		defer func() {
			if closeErr := s.Close(); closeErr != nil {
				slog.Warn("failed to close Titus scanner", "error", closeErr)
			}
			if err != nil {
				out.CloseWithError(err)
				return
			}
			out.Close()
		}()

		for item := range scanned.Range() {
			out.Send(item)
		}
		// s.Scan itself never errors, but pipeline.Pipe records any upstream
		// stage failure (e.g. a cloud lister/extractor) on the scanned stream
		// via in.Wait(). Propagate it to out so the module reports failure
		// instead of silent partial success.
		if waitErr := scanned.Wait(); waitErr != nil {
			err = waitErr
			return
		}
		// Drain the timed-out retry queue once all inputs are scanned.
		if flushErr := s.Flush(out); flushErr != nil {
			slog.Warn("failed to flush timed-out secret matches", "error", flushErr)
		}
	}()
}

// Scan is a pipeline-compatible method that scans a ScanInput for secrets
// and sends SecretScanResult values to the output pipeline.
func (s *SecretScanner) Scan(input output.ScanInput, out *pipeline.P[SecretScanResult]) error {
	if s.ps == nil {
		return fmt.Errorf("secret scanner not started or already closed")
	}

	if input.PathFilterable && s.ignorePath != nil && s.ignorePath(input.Label) {
		slog.Debug("skipping ignored path", "label", input.Label, "resource", input.ResourceID)
		return nil
	}

	blobID := types.ComputeBlobID(input.Content)
	matches, err := s.ps.scanContent(input.Content, blobID, provenanceFromScanInput(input))
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

// Flush recovers matches that hit Titus' regexp timeout retry path and emits
// them to the output pipeline. Titus withholds such matches from the per-blob
// Scan results and queues them behind the matcher's drain; without Flush they
// are silently dropped. Call once after all Scan calls have completed and
// before the output pipeline is closed.
func (s *SecretScanner) Flush(out *pipeline.P[SecretScanResult]) error {
	if s.ps == nil {
		return nil
	}

	matches, err := s.ps.drainTimedOut()
	if err != nil {
		return fmt.Errorf("flush: %w", err)
	}

	for _, match := range matches {
		// Recovered matches do not carry the original ScanInput; reconstruct it
		// from the provenance stored at scan time so validation and the emitted
		// result get the same resource metadata as the immediate-match path.
		input := s.scanInputFor(match.BlobID)
		if s.validate && s.engine != nil {
			s.validateMatch(match, input.ResourceID)
		}
		out.Send(toScanResult(input, match))
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

// scanInputFor reconstructs the ScanInput for a recovered match from the
// ExtendedProvenance stored when the blob was first scanned. Returns a zero
// ScanInput (and logs) if provenance is unavailable.
func (s *SecretScanner) scanInputFor(blobID types.BlobID) output.ScanInput {
	prov, err := s.ps.store.GetProvenance(blobID)
	if err != nil {
		slog.Warn("failed to load provenance for recovered match", "blob", blobID.Hex(), "error", err)
		return output.ScanInput{}
	}
	ext, ok := prov.(types.ExtendedProvenance)
	if !ok {
		slog.Warn("unexpected provenance type for recovered match", "blob", blobID.Hex(), "type", fmt.Sprintf("%T", prov))
		return output.ScanInput{}
	}
	return scanInputFromProvenance(ext)
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
		Platform:     input.Platform,
		Label:        input.Label,
		Match:        match,
	}
}

// provenanceFromScanInput and scanInputFromProvenance are inverses: they map a
// ScanInput's resource metadata to/from the ExtendedProvenance payload stored
// with each blob. Keeping the payload key set in this one pair prevents the
// scan-time and drain-time sides from drifting and silently losing metadata.
func provenanceFromScanInput(input output.ScanInput) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]any{
			"platform":      input.Platform,
			"resource_id":   input.ResourceID,
			"resource_type": input.ResourceType,
			"region":        input.Region,
			"account_id":    input.AccountID,
			"subresource":   input.Label,
		},
	}
}

func scanInputFromProvenance(prov types.ExtendedProvenance) output.ScanInput {
	str := func(key string) string {
		if v, ok := prov.Payload[key].(string); ok {
			return v
		}
		return ""
	}
	return output.ScanInput{
		Platform:     str("platform"),
		ResourceID:   str("resource_id"),
		ResourceType: str("resource_type"),
		Region:       str("region"),
		AccountID:    str("account_id"),
		Label:        str("subresource"),
	}
}
