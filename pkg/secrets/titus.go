package secrets

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/utils"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// persistentScanner wraps Titus matcher and store with persistent SQLite database.
type persistentScanner struct {
	matcher matcher.Matcher
	store   store.Store
	dbPath  string
	ruleMap map[string]*types.Rule
}

// newPersistentScanner creates a new persistent Titus scanner.
// If dbPath is empty, defaults to aurelian-output/titus.db.
func newPersistentScanner(dbPath string) (*persistentScanner, error) {
	if dbPath == "" {
		dbPath = "aurelian-output/titus.db"
	}

	if err := utils.EnsureOutputDirectory(); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	s, err := store.New(store.Config{Path: dbPath})
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("failed to load builtin rules: %w", err)
	}

	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: 3,
	})
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("failed to create matcher: %w", err)
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	return &persistentScanner{
		matcher: m,
		store:   s,
		dbPath:  dbPath,
		ruleMap: ruleMap,
	}, nil
}

// scanContent scans content and stores results in the persistent database.
// Supports incremental scanning by checking if blob was already scanned.
func (ps *persistentScanner) scanContent(content []byte, blobID types.BlobID, provenance types.Provenance) ([]*types.Match, error) {
	exists, err := ps.store.BlobExists(blobID)
	if err != nil {
		return nil, fmt.Errorf("failed to check blob existence: %w", err)
	}

	if exists {
		return ps.store.GetMatches(blobID)
	}

	if err := ps.store.AddBlob(blobID, int64(len(content))); err != nil {
		return nil, fmt.Errorf("failed to store blob: %w", err)
	}

	if err := ps.store.AddProvenance(blobID, provenance); err != nil {
		return nil, fmt.Errorf("failed to store provenance: %w", err)
	}

	matches, err := ps.matcher.MatchWithBlobID(content, blobID)
	if err != nil {
		return nil, fmt.Errorf("failed to match content: %w", err)
	}

	for _, match := range matches {
		if err := ps.storeMatchAndFinding(match); err != nil {
			return nil, err
		}
	}

	return matches, nil
}

func (ps *persistentScanner) storeMatchAndFinding(match *types.Match) error {
	if err := ps.store.AddMatch(match); err != nil {
		return fmt.Errorf("failed to store match: %w", err)
	}

	r, ok := ps.ruleMap[match.RuleID]
	if !ok {
		return fmt.Errorf("rule not found: %s", match.RuleID)
	}

	findingID := types.ComputeFindingID(r.StructuralID, match.Groups)
	exists, err := ps.store.FindingExists(findingID)
	if err != nil {
		return fmt.Errorf("failed to check finding existence: %w", err)
	}

	if !exists {
		finding := &types.Finding{
			ID:     findingID,
			RuleID: match.RuleID,
			Groups: match.Groups,
		}
		if err := ps.store.AddFinding(finding); err != nil {
			return fmt.Errorf("failed to store finding: %w", err)
		}
	}

	return nil
}

// close closes the matcher and store, releasing resources.
func (ps *persistentScanner) close() error {
	if err := ps.matcher.Close(); err != nil {
		ps.store.Close()
		return fmt.Errorf("failed to close matcher: %w", err)
	}

	if err := ps.store.Close(); err != nil {
		return fmt.Errorf("failed to close store: %w", err)
	}

	return nil
}
