package plugin

import (
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// Finding represents a security vulnerability or misconfiguration discovered by an analyzer.
// Analyzers (both YAML rules and Go modules) return []Finding from their Run() method.
type Finding struct {
	model.BaseAurelianModel
	// RuleID is the machine-readable identifier for the detection rule
	// Examples: "lambda-no-auth-function-url", "s3-public-bucket"
	RuleID string

	// Severity indicates impact level
	// Valid values: "low", "medium", "high", "critical"
	Severity string

	// Name is the human-readable name of the finding
	// Example: "Lambda Function URL Without Authentication"
	Name string

	// Description provides detailed explanation of the vulnerability
	Description string

	// Resource is the cloud resource with the vulnerability
	Resource output.AWSResource

	// References contains external documentation links (optional)
	References []string

	// Recommendation provides remediation guidance (optional)
	Recommendation string
}
