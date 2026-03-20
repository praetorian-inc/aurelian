package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// Risk represents a security vulnerability or configuration issue discovered
// during cloud resource scanning. This type is used by security scanners
// (CDK scanner, Apollo IAM analyzer, etc.) to report security findings.
type Risk struct {
	model.BaseAurelianModel

	// Target is the cloud resource with the vulnerability (optional, can be nil for general findings)
	Target *AWSResource `json:"target,omitempty"`

	// Name is the risk identifier (e.g., "s3-bucket-public-access", "cdk-bootstrap-missing")
	Name string `json:"name"`

	// DNS is a unique identifier for this risk instance
	// Often: account ID, organization ID, or resource identifier
	DNS string `json:"dns"`

	// Status represents severity level
	// Valid values:
	//   "TL" - Low severity
	//   "TM" - Medium severity
	//   "TH" - High severity
	//   "TC" - Critical severity
	Status string `json:"status"`

	// Source identifies the scanner that found this risk
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
