package escalation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// LoadAndMergeModelFiles reads model.json files from disk and merges them
// into a single org-wide Model. Returns an error if any file is unreadable
// or contains invalid JSON.
func LoadAndMergeModelFiles(paths []string) (*Model, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("LoadAndMergeModelFiles: no input files provided")
	}

	models := make([]*Model, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		var m Model
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", filepath.Base(path), err)
		}
		models = append(models, &m)
	}

	return MergeModels(models)
}

// GlobModelFiles returns sorted paths to all .json files in a directory.
// Paths in exclude are omitted (compared after filepath.Abs normalization).
func GlobModelFiles(dir string, exclude ...string) ([]string, error) {
	pattern := filepath.Join(dir, "*.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("globbing %s: %w", pattern, err)
	}

	excludeSet := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		abs, err := filepath.Abs(e)
		if err == nil {
			excludeSet[abs] = true
		}
	}

	var filtered []string
	for _, m := range matches {
		abs, err := filepath.Abs(m)
		if err == nil && excludeSet[abs] {
			continue
		}
		filtered = append(filtered, m)
	}

	sort.Strings(filtered)
	return filtered, nil
}

// ModelStats holds summary statistics about a merged model.
type ModelStats struct {
	Accounts        int
	Principals      int
	Resources       int
	StructuralFacts int
}

// MergeStats returns summary statistics for a model.
func MergeStats(m *Model) ModelStats {
	return ModelStats{
		Accounts:        len(m.Accounts),
		Principals:      len(m.Principals),
		Resources:       len(m.Resources),
		StructuralFacts: len(m.StructuralFacts),
	}
}
