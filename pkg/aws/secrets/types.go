package secrets

// ExtractedContent represents content extracted from an AWS resource for secret scanning.
type ExtractedContent struct {
	Content    []byte
	Provenance Provenance
}

// Provenance describes the origin of extracted content.
type Provenance struct {
	Platform     string
	ResourceType string
	ResourceID   string
	Region       string
	AccountID    string
	FilePath     string
}

// ScanOptions configures the find-secrets scanner.
type ScanOptions struct {
	Profile     string
	ProfileDir  string
	Regions     []string
	Concurrency int
	// DBPath is the path for the Titus SQLite database (empty = default)
	DBPath string
	// Verify enables secret validation against source APIs
	Verify bool
	// Resource types to scan (or ["all"] for all supported types)
	ResourceTypes []string
	// CloudWatch-specific options
	MaxEvents   int
	MaxStreams  int
	NewestFirst bool
}
