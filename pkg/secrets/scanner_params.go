package secrets

import "path/filepath"

const defaultDBFilename = "titus.db"

// ScannerConfig holds parameters for the secret scanner.
// Embed this in module configs that need secret scanning.
type ScannerConfig struct {
	DBPath             string   `param:"db-path" desc:"Path for Titus SQLite database"`
	DisabledTitusRules []string `param:"disabled-titus-rules" desc:"Rule IDs to exclude from scanning"`
	Validate           bool     `param:"validate" desc:"Validate detected secrets against their source APIs" default:"false"`
	IgnoreFile         string   `param:"ignore-file" desc:"Path to gitignore-style file for skipping paths; when empty uses a default list" default:""`
	Ruleset            string   `param:"ruleset" desc:"Titus ruleset to apply; empty string disables ruleset filtering" default:"default"`
}

// DefaultDBPath returns the default database path for the given output directory.
func DefaultDBPath(outputDir string) string {
	return filepath.Join(outputDir, defaultDBFilename)
}
