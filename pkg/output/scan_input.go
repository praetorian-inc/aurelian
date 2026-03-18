package output

// ScanInput represents extracted content from a cloud resource ready for secret scanning.
type ScanInput struct {
	// Content is the raw bytes to scan for secrets.
	Content []byte

	// ResourceID is the unique identifier for the source resource (ARN, Azure resource ID, or GCP resource name).
	ResourceID string

	// ResourceType is the cloud-native resource type (e.g. "AWS::Lambda::Function").
	ResourceType string

	// Region is the region or location where the resource lives.
	Region string

	// AccountID is the account scope (AWS account ID, Azure subscription ID, or GCP project ID).
	AccountID string

	// Platform is the cloud provider: "aws", "azure", or "gcp".
	Platform string

	// Label describes the sub-location within the resource (e.g. "handler.py", "WebApp AppSettings", stream name).
	Label string

	// PathFilterable indicates Label is a filesystem path eligible for ignore-pattern filtering.
	// Set to true only when Label is an archive-relative or filesystem path (e.g. Lambda ZIP entries).
	// Leave false for semantic labels like "UserData" or "ECS Task Definition".
	PathFilterable bool
}

// ScanInputFromAWSResource creates a ScanInput by mapping common fields from an AWSResource.
func ScanInputFromAWSResource(r AWSResource, label string, content []byte) ScanInput {
	return ScanInput{
		Content:      content,
		ResourceID:   r.ARN,
		ResourceType: r.ResourceType,
		Region:       r.Region,
		AccountID:    r.AccountRef,
		Platform:     "aws",
		Label:        label,
	}
}

// ScanInputFromAzureResource creates a ScanInput by mapping common fields from an AzureResource.
func ScanInputFromAzureResource(r AzureResource, label string, content []byte) ScanInput {
	return ScanInput{
		Content:      content,
		ResourceID:   r.ResourceID,
		ResourceType: r.ResourceType,
		Region:       r.Location,
		AccountID:    r.SubscriptionID,
		Platform:     "azure",
		Label:        label,
	}
}

// ScanInputFromGCPResource creates a ScanInput by mapping common fields from a GCPResource.
func ScanInputFromGCPResource(r GCPResource, label string, content []byte) ScanInput {
	return ScanInput{
		Content:      content,
		ResourceID:   r.ResourceID,
		ResourceType: r.ResourceType,
		Region:       r.Location,
		AccountID:    r.ProjectID,
		Platform:     "gcp",
		Label:        label,
	}
}
