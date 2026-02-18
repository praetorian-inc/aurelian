package output

// AWSResource represents an AWS cloud resource discovered during scanning.
// This type replaces the Tabularium AWSResource type to eliminate the
// dependency on Tabularium in Aurelian.
type AWSResource struct {
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

// NewAWSResource constructs an AWSResource with the required core fields.
// Additional optional fields should be set by the caller as needed.
func NewAWSResource(platform, region, resourceType, accountRef, resourceID string) AWSResource {
	resource := AWSResource{
		Platform:     platform,
		Region:       region,
		ResourceType: resourceType,
		AccountRef:   accountRef,
		ResourceID:   resourceID,
	}

	return resource
}
