package output

// AWSResource represents an AWS cloud resource discovered during scanning.
// This type replaces the Tabularium AWSResource type to eliminate the
// dependency on Tabularium in Aurelian.
type AWSResource struct {
	// ResourceType is the AWS resource type identifier (e.g. "AWS::Lambda::Function", "AWS::S3::Bucket")
	ResourceType string `json:"resource_type"`

	// ResourceID is the unique identifier for this resource (typically an ARN)
	ResourceID string `json:"resource_id"`

	// ARN is the AWS ARN for this resource when applicable
	ARN string `json:"arn,omitempty"`

	// AccountRef is the AWS account ID (e.g. "123456789012")
	AccountRef string `json:"account_ref"`

	// Region is the AWS region (optional, omit if not applicable)
	Region string `json:"region,omitempty"`

	// DisplayName is a human-readable name for the resource (optional)
	DisplayName string `json:"display_name,omitempty"`

	// Properties contains additional resource metadata as key-value pairs (optional)
	Properties map[string]any `json:"properties,omitempty"`

	// URLs are associated HTTP(S) endpoints for this resource (optional)
	URLs []string `json:"urls,omitempty"`

	// IPs are associated IP addresses for this resource (optional)
	IPs []string `json:"ips,omitempty"`
}

// NewAWSResource constructs an AWSResource with the required core fields.
// Additional optional fields should be set by the caller as needed.
func NewAWSResource(region, resourceType, accountRef, resourceID string) AWSResource {
	resource := AWSResource{
		Region:       region,
		ResourceType: resourceType,
		AccountRef:   accountRef,
		ResourceID:   resourceID,
	}

	return resource
}
