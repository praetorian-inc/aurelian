package output

// CloudResource represents a universal cloud resource across AWS, Azure, and GCP.
// This type replaces the Tabularium GCPResource/AWSResource/AzureResource types
// to eliminate the dependency on Tabularium in Aurelian.
type CloudResource struct {
	// Platform identifies the cloud provider: "aws", "azure", or "gcp"
	Platform string `json:"platform"`

	// ResourceType is the cloud-specific resource type identifier
	// Examples:
	//   AWS: "AWS::Lambda::Function", "AWS::S3::Bucket"
	//   Azure: "Microsoft.Storage/storageAccounts"
	//   GCP: "cloudresourcemanager.googleapis.com/Project"
	ResourceType string `json:"resource_type"`

	// ResourceID is the unique identifier for this resource
	// Examples:
	//   AWS: ARN ("arn:aws:s3:::bucket-name")
	//   Azure: Resource ID ("/subscriptions/.../resourceGroups/...")
	//   GCP: Full resource path ("projects/my-project-123")
	ResourceID string `json:"resource_id"`

	// ARN is the AWS ARN for this resource when applicable
	ARN string `json:"arn,omitempty"`

	// AccountRef is the account/subscription/project identifier
	// Examples:
	//   AWS: Account ID ("123456789012")
	//   Azure: Subscription ID ("sub-123")
	//   GCP: Organization or project parent ("organizations/123456789")
	AccountRef string `json:"account_ref"`

	// Region is the cloud region (optional, omit if not applicable)
	Region string `json:"region,omitempty"`

	// DisplayName is a human-readable name for the resource (optional)
	DisplayName string `json:"display_name,omitempty"`

	// Properties contains additional resource metadata as key-value pairs (optional)
	// This flexible map allows cloud-specific attributes without rigid schema
	Properties map[string]any `json:"properties,omitempty"`

	// URLs are associated HTTP(S) endpoints for this resource (optional)
	URLs []string `json:"urls,omitempty"`

	// IPs are associated IP addresses for this resource (optional)
	IPs []string `json:"ips,omitempty"`
}

// NewCloudResource constructs a CloudResource with the required core fields.
// Additional optional fields should be set by the caller as needed.
func NewCloudResource(platform, region, resourceType, accountRef, resourceID string) CloudResource {
	resource := CloudResource{
		Platform:     platform,
		Region:       region,
		ResourceType: resourceType,
		AccountRef:   accountRef,
		ResourceID:   resourceID,
	}

	return resource
}

// SecretFinding represents a secret detection result from scanning cloud resources.
// This type is used by secret scanning capabilities (e.g., scanning S3 buckets,
// Azure storage, GCP buckets) to report discovered secrets.
type SecretFinding struct {
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
	Target *CloudResource `json:"target,omitempty"`

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
