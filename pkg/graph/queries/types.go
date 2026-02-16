package queries

// QueryMetadata describes a Cypher query loaded from YAML
type QueryMetadata struct {
	ID          string   `yaml:"id"`          // Unique identifier (e.g., "aws/enrich/privesc/method_01")
	Name        string   `yaml:"name"`        // Human-readable name
	Platform    string   `yaml:"platform"`    // aws, azure, gcp
	Type        string   `yaml:"type"`        // enrich, analysis
	Category    string   `yaml:"category"`    // privesc, resource-to-role, admin-detection
	Description string   `yaml:"description"` // What this query does
	Severity    string   `yaml:"severity"`    // low, medium, high, critical
	Order       int      `yaml:"order"`       // Execution order (1-N)
	Cypher      string   `yaml:"cypher"`      // The actual Cypher query
	Parameters  []string `yaml:"parameters"`  // List of required parameters
}

// Query represents a loaded and parsed query
type Query struct {
	Metadata QueryMetadata
	Cypher   string // Processed Cypher (with parameter validation)
}
