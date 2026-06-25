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
	if input.PathFilterable && s.ignorePath != nil && s.ignorePath(input.Label) {
		slog.Debug("skipping ignored path", "label", input.Label, "resource", input.ResourceID)
		return nil
	}

	blobID := types.ComputeBlobID(input.Content)
	provenance := types.ExtendedProvenance{
		Payload: map[string]any{
			"platform":      input.Platform,
			"resource_id":   input.ResourceID,
			"resource_type": input.ResourceType,
			"region":        input.Region,
			"account_id":    input.AccountID,
			"subresource":   input.Label,
		},
	}

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

// ScanAndFlush runs Scan over every input and then flushes any timed-out retry
// matches into the same output pipeline, closing out when complete. It is a
// drop-in replacement for `pipeline.Pipe(in, s.Scan, out, opts...)` that also
// drains Titus' deferred-retry queue, so secrets that hit the regexp timeout
// path are not silently dropped. Like pipeline.Pipe it returns immediately and
// runs asynchronously, closing out when done. The drain runs only after every
// Scan has completed, since the matcher's queue is shared across all scanned
// blobs.
func (s *SecretScanner) ScanAndFlush(in *pipeline.P[output.ScanInput], out *pipeline.P[SecretScanResult], opts ...*pipeline.PipeOpts) {
	scanned := pipeline.New[SecretScanResult]()
	pipeline.Pipe(in, s.Scan, scanned, opts...)

	go func() {
		// Safety net: guarantees out is closed even if a stage below panics.
		// No-op once CloseWithError/Close has already run (guarded by closeOnce).
		defer out.Close()

		for item := range scanned.Range() {
			out.Send(item)
		}
		// s.Scan itself never errors, but pipeline.Pipe records any upstream
		// stage failure (e.g. a cloud lister/extractor) on the scanned stream
		// via in.Wait(). Propagate it to out so the module reports failure
		// instead of silent partial success.
		if err := scanned.Wait(); err != nil {
			out.CloseWithError(err)
			return
		}
		// Drain the timed-out retry queue once all inputs are scanned.
		if err := s.Flush(out); err != nil {
			slog.Warn("failed to flush timed-out secret matches", "error", err)
		}
	}()
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
		return fmt.Errorf("failed to drain timed-out matches: %w", err)
	}

	for _, match := range matches {
		if s.validate && s.engine != nil {
			s.validateMatch(match, match.RuleID)
		}
		out.Send(s.drainedToScanResult(match))
	}
	return nil
}

// drainedToScanResult builds a SecretScanResult for a recovered match.
// Recovered matches do not carry the original ScanInput, so the resource
// metadata is reconstructed from the ExtendedProvenance stored at scan time and
// fed through the same toScanResult constructor as immediate matches — keeping a
// single place that maps metadata onto SecretScanResult.
func (s *SecretScanner) drainedToScanResult(match *types.Match) SecretScanResult {
	input := output.ScanInput{}

	prov, err := s.ps.store.GetProvenance(match.BlobID)
	if err != nil {
		slog.Warn("failed to load provenance for recovered match", "blob", match.BlobID.Hex(), "error", err)
		return toScanResult(input, match)
	}

	if ext, ok := prov.(types.ExtendedProvenance); ok {
		str := func(key string) string {
			if v, ok := ext.Payload[key].(string); ok {
				return v
			}
			return ""
		}
		input.Platform = str("platform")
		input.ResourceID = str("resource_id")
		input.ResourceType = str("resource_type")
		input.Region = str("region")
		input.AccountID = str("account_id")
		input.Label = str("subresource")
	}

	return toScanResult(input, match)
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
