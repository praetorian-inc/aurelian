package secrets

import "path/filepath"

const defaultDBFilename = "titus.db"

// ScannerConfig holds parameters for the secret scanner.
// Embed this in module configs that need secret scanning.
type ScannerConfig struct {
	DBPath             string   `param:"db-path" desc:"Path for Titus SQLite database"`
	DisabledTitusRules []string `param:"disabled-titus-rules" desc:"Rule IDs to exclude from scanning"`
}

// DefaultDBPath returns the default database path for the given output directory.
func DefaultDBPath(outputDir string) string {
	return filepath.Join(outputDir, defaultDBFilename)
}
