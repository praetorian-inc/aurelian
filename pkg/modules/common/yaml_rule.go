package common

// YAMLRule represents a declarative security analysis rule.
// Rules are loaded from YAML files and evaluated against CloudResource properties.
type YAMLRule struct {
	// ID is the machine-readable rule identifier
	ID string `yaml:"id"`

	// Name is the human-readable rule name
	Name string `yaml:"name"`

	// Platform identifies the cloud provider: "aws", "azure", "gcp"
	Platform string `yaml:"platform"`

	// ResourceType is the cloud resource type this rule applies to
	// Examples: "AWS::Lambda::Function", "AWS::S3::Bucket"
	ResourceType string `yaml:"resource_type"`

	// Severity indicates impact level: "low", "medium", "high", "critical"
	Severity string `yaml:"severity"`

	// Description provides detailed explanation of the vulnerability
	Description string `yaml:"description"`

	// References contains external documentation links
	References []string `yaml:"references"`

	// Recommendation provides remediation guidance (optional)
	Recommendation string `yaml:"recommendation,omitempty"`

	// Match defines the conditions that must ALL be true (implicit AND)
	Match []MatchCondition `yaml:"match"`
}

// MatchCondition represents a single property check.
// Exactly one operator field should be set per condition.
type MatchCondition struct {
	// Field is the property path to check (e.g., "FunctionUrl", "PublicAccessBlockConfiguration.BlockPublicAcls")
	Field string `yaml:"field"`

	// Operators (exactly one should be set):
	Equals       any     `yaml:"equals,omitempty"`        // Exact match
	NotEquals    any     `yaml:"not_equals,omitempty"`    // Negation
	Exists       *bool   `yaml:"exists,omitempty"`        // Property presence (pointer to distinguish unset vs false)
	Contains     string  `yaml:"contains,omitempty"`      // Substring or list membership
	Regex        string  `yaml:"regex,omitempty"`         // Pattern match
	GreaterThan  float64 `yaml:"greater_than,omitempty"`  // Numeric comparison
	LessThan     float64 `yaml:"less_than,omitempty"`     // Numeric comparison
}
