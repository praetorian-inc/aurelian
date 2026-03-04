package output

// ScanInput represents extracted content from an AWS resource ready for secret scanning.
type ScanInput struct {
	// Content is the raw bytes to scan for secrets.
	Content []byte

	// ResourceID is the AWS ARN of the source resource.
	ResourceID string

	// ResourceType is the AWS Cloud Control type (e.g. "AWS::Lambda::Function").
	ResourceType string

	// Region is the AWS region where the resource lives.
	Region string

	// AccountID is the AWS account ID that owns the resource.
	AccountID string

	// Label describes what this content is (e.g. "UserData", "handler.py", "template.yaml").
	Label string
}

// ScanInputFromAWSResource creates a ScanInput by mapping common fields from an AWSResource.
func ScanInputFromAWSResource(r AWSResource, label string, content []byte) ScanInput {
	return ScanInput{
		Content:      content,
		ResourceID:   r.ARN,
		ResourceType: r.ResourceType,
		Region:       r.Region,
		AccountID:    r.AccountRef,
		Label:        label,
	}
}
