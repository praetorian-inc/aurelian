package scanner

import (
	"fmt"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// PersistentScanner wraps Titus matcher and store
type PersistentScanner struct {
	matcher matcher.Matcher
	store   store.Store
	dbPath  string
	ruleMap map[string]*types.Rule // map of RuleID to Rule for finding creation
}

// NewPersistentScanner creates a new Titus scanner with in-memory storage
// The dbPath parameter is accepted for API compatibility but ignored;
// storage is always in-memory.
func NewPersistentScanner(dbPath string) (*PersistentScanner, error) {
	// Always use in-memory storage (file-based SQLite was removed in titus v0.3.0)
	s, err := store.New(store.Config{
		Path: ":memory:",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	// Load builtin rules
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("failed to load builtin rules: %w", err)
	}

	// Create matcher
	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: 3, // Default context lines
	})
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("failed to create matcher: %w", err)
	}

	// Create rule map for finding ID computation
	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	return &PersistentScanner{
		matcher: m,
		store:   s,
		dbPath:  ":memory:",
		ruleMap: ruleMap,
	}, nil
}

// ScanContent scans content and stores results in the persistent database
// Supports incremental scanning by checking if blob already scanned
func (ps *PersistentScanner) ScanContent(content []byte, blobID types.BlobID, provenance types.Provenance) ([]*types.Match, error) {
	// Check if blob already scanned (incremental scanning support)
	exists, err := ps.store.BlobExists(blobID)
	if err != nil {
		return nil, fmt.Errorf("failed to check blob existence: %w", err)
	}

	if exists {
		// Blob already scanned, return existing matches
		return ps.store.GetMatches(blobID)
	}

	// Store blob
	if err := ps.store.AddBlob(blobID, int64(len(content))); err != nil {
		return nil, fmt.Errorf("failed to store blob: %w", err)
	}

	// Store provenance
	if err := ps.store.AddProvenance(blobID, provenance); err != nil {
		return nil, fmt.Errorf("failed to store provenance: %w", err)
	}

	// Match content
	matches, err := ps.matcher.MatchWithBlobID(content, blobID)
	if err != nil {
		return nil, fmt.Errorf("failed to match content: %w", err)
	}

	// Store matches and create findings
	for _, match := range matches {
		if err := ps.store.AddMatch(match); err != nil {
			return nil, fmt.Errorf("failed to store match: %w", err)
		}

		// Create finding (deduplicated by finding ID)
		rule, ok := ps.ruleMap[match.RuleID]
		if !ok {
			return nil, fmt.Errorf("rule not found: %s", match.RuleID)
		}

		findingID := types.ComputeFindingID(rule.StructuralID, match.Groups)
		exists, err := ps.store.FindingExists(findingID)
		if err != nil {
			return nil, fmt.Errorf("failed to check finding existence: %w", err)
		}

		if !exists {
			finding := &types.Finding{
				ID:     findingID,
				RuleID: match.RuleID,
				Groups: match.Groups,
			}
			if err := ps.store.AddFinding(finding); err != nil {
				return nil, fmt.Errorf("failed to store finding: %w", err)
			}
		}
	}

	return matches, nil
}

// Close closes the matcher and store, releasing resources
func (ps *PersistentScanner) Close() error {
	// Close matcher first
	if err := ps.matcher.Close(); err != nil {
		// Continue to close store even if matcher close fails
		ps.store.Close()
		return fmt.Errorf("failed to close matcher: %w", err)
	}

	// Close store
	if err := ps.store.Close(); err != nil {
		return fmt.Errorf("failed to close store: %w", err)
	}

	return nil
}

// DBPath returns the configured database path
func (ps *PersistentScanner) DBPath() string {
	return ps.dbPath
}
