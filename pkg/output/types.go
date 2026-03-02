package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// SecretFinding represents a secret detection result from scanning cloud resources.
// This type is used by secret scanning capabilities (e.g., scanning S3 buckets,
// Azure storage, GCP buckets) to report discovered secrets.
type SecretFinding struct {
	model.BaseAurelianModel

	// ResourceRef is a reference to the cloud resource where the secret was found
	// Examples:
	//   AWS S3: "arn:aws:s3:::bucket-name/path/to/file"
	//   GCP: "projects/my-project/secrets/secret-name"
	//   Azure: "/subscriptions/.../secrets/secret-name"
	ResourceRef string `json:"resource_ref"`

	// RuleName is the human-readable name of the detection rule that matched
	// Examples: "AWS Access Key", "GitHub Token", "Private Key"
	RuleName string `json:"rule_name"`

	// RuleTextID is the machine-readable identifier for the detection rule
	// Examples: "aws-access-key-id", "github-token", "private-key-pem"
	RuleTextID string `json:"rule_text_id"`

	// Match is the actual secret value that was detected (optional)
	// Note: May be redacted or truncated for security
	Match string `json:"match,omitempty"`

	// FilePath is the path within the resource where the secret was found (optional)
	// Example: "config/credentials.yaml"
	FilePath string `json:"file_path,omitempty"`

	// LineNumber is the line number where the secret was found (optional, 0 if not applicable)
	LineNumber int `json:"line_number,omitempty"`

	// Confidence indicates the detection confidence level
	// Valid values: "low", "medium", "high", "critical"
	Confidence string `json:"confidence"`
}

// Risk represents a security vulnerability or configuration issue discovered
// during cloud resource scanning. This type is used by security scanners
// (CDK scanner, Apollo IAM analyzer, etc.) to report security findings.
type Risk struct {
	// Target is the cloud resource with the vulnerability (optional, can be nil for general findings)
	Target *AWSResource `json:"target,omitempty"`

	// Name is the risk identifier (e.g., "s3-bucket-public-access", "cdk-bootstrap-missing")
	Name string `json:"name"`

	// DNS is a unique identifier for this risk instance
	// Often: account ID, organization ID, or resource identifier
	// Examples: "123456789012", "organizations/987654321"
	DNS string `json:"dns"`

	// Status represents severity level
	// Valid values:
	//   "TL" - Low severity
	//   "TM" - Medium severity
	//   "TH" - High severity
	//   "TC" - Critical severity
	Status string `json:"status"`

	// Source identifies the scanner that found this risk
	// Examples: "aurelian-cdk-scanner", "apollo-iam-analysis", "apollo-resource-analysis"
	Source string `json:"source"`

	// Description provides detailed explanation of the vulnerability
	Description string `json:"description"`

	// Impact describes potential consequences of this vulnerability
	Impact string `json:"impact"`

	// Recommendation provides remediation guidance
	Recommendation string `json:"recommendation"`

	// References contains external documentation links
	References string `json:"references"`

	// Comment provides additional context (optional)
	Comment string `json:"comment,omitempty"`
}
