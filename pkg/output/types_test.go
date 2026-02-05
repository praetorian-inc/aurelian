package output

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCloudResourceJSONSerialization tests that CloudResource can be marshaled and unmarshaled to/from JSON
func TestCloudResourceJSONSerialization(t *testing.T) {
	resource := CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "arn:aws:s3:::test-bucket",
		AccountRef:   "123456789012",
		Region:       "us-west-2",
		DisplayName:  "Test Bucket",
		Properties:   map[string]any{"versioning": true, "encryption": "AES256"},
		URLs:         []string{"https://test-bucket.s3.amazonaws.com"},
		IPs:          []string{"52.218.224.1"},
	}

	// Marshal to JSON
	data, err := json.Marshal(resource)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal back
	var decoded CloudResource
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	// Verify fields
	assert.Equal(t, "aws", decoded.Platform)
	assert.Equal(t, "AWS::S3::Bucket", decoded.ResourceType)
	assert.Equal(t, "arn:aws:s3:::test-bucket", decoded.ResourceID)
	assert.Equal(t, "123456789012", decoded.AccountRef)
	assert.Equal(t, "us-west-2", decoded.Region)
	assert.Equal(t, "Test Bucket", decoded.DisplayName)
	assert.Equal(t, true, decoded.Properties["versioning"])
	assert.Equal(t, "AES256", decoded.Properties["encryption"])
	assert.Equal(t, []string{"https://test-bucket.s3.amazonaws.com"}, decoded.URLs)
	assert.Equal(t, []string{"52.218.224.1"}, decoded.IPs)
}

// TestCloudResourceGCPFormat tests GCP-specific resource format
func TestCloudResourceGCPFormat(t *testing.T) {
	resource := CloudResource{
		Platform:     "gcp",
		ResourceType: "cloudresourcemanager.googleapis.com/Project",
		ResourceID:   "projects/my-project-123",
		AccountRef:   "organizations/123456789",
		DisplayName:  "My Project",
		Properties:   map[string]any{"projectNumber": "987654321", "lifecycleState": "ACTIVE"},
	}

	data, err := json.Marshal(resource)
	assert.NoError(t, err)

	var decoded CloudResource
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	assert.Equal(t, "gcp", decoded.Platform)
	assert.Equal(t, "cloudresourcemanager.googleapis.com/Project", decoded.ResourceType)
	assert.Equal(t, "projects/my-project-123", decoded.ResourceID)
}

// TestCloudResourceAzureFormat tests Azure-specific resource format
func TestCloudResourceAzureFormat(t *testing.T) {
	resource := CloudResource{
		Platform:     "azure",
		ResourceType: "Microsoft.Storage/storageAccounts",
		ResourceID:   "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.Storage/storageAccounts/testacct",
		AccountRef:   "sub-123",
		Region:       "westus2",
		DisplayName:  "testacct",
		Properties:   map[string]any{"sku": "Standard_LRS", "kind": "StorageV2"},
	}

	data, err := json.Marshal(resource)
	assert.NoError(t, err)

	var decoded CloudResource
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	assert.Equal(t, "azure", decoded.Platform)
	assert.Equal(t, "Microsoft.Storage/storageAccounts", decoded.ResourceType)
}

// TestCloudResourceMinimal tests minimal required fields
func TestCloudResourceMinimal(t *testing.T) {
	resource := CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		AccountRef:   "123456789012",
	}

	data, err := json.Marshal(resource)
	assert.NoError(t, err)

	var decoded CloudResource
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	assert.Equal(t, "aws", decoded.Platform)
	assert.Equal(t, "AWS::EC2::Instance", decoded.ResourceType)
	assert.Equal(t, "i-1234567890abcdef0", decoded.ResourceID)
	assert.Equal(t, "123456789012", decoded.AccountRef)
	// Optional fields should be empty/zero values
	assert.Empty(t, decoded.Region)
	assert.Empty(t, decoded.DisplayName)
	assert.Nil(t, decoded.Properties)
	assert.Nil(t, decoded.URLs)
	assert.Nil(t, decoded.IPs)
}

// TestSecretFindingJSONSerialization tests that SecretFinding can be marshaled and unmarshaled to/from JSON
func TestSecretFindingJSONSerialization(t *testing.T) {
	finding := SecretFinding{
		ResourceRef: "arn:aws:s3:::test-bucket/config.yaml",
		RuleName:    "AWS Access Key",
		RuleTextID:  "aws-access-key-id",
		Match:       "AKIAIOSFODNN7EXAMPLE",
		FilePath:    "config.yaml",
		LineNumber:  42,
		Confidence:  "high",
	}

	// Marshal to JSON
	data, err := json.Marshal(finding)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal back
	var decoded SecretFinding
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	// Verify fields
	assert.Equal(t, "arn:aws:s3:::test-bucket/config.yaml", decoded.ResourceRef)
	assert.Equal(t, "AWS Access Key", decoded.RuleName)
	assert.Equal(t, "aws-access-key-id", decoded.RuleTextID)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", decoded.Match)
	assert.Equal(t, "config.yaml", decoded.FilePath)
	assert.Equal(t, 42, decoded.LineNumber)
	assert.Equal(t, "high", decoded.Confidence)
}

// TestSecretFindingMinimal tests minimal required fields
func TestSecretFindingMinimal(t *testing.T) {
	finding := SecretFinding{
		ResourceRef: "projects/my-project/secrets/api-key",
		RuleName:    "Generic Secret",
		RuleTextID:  "generic-secret",
		Confidence:  "medium",
	}

	data, err := json.Marshal(finding)
	assert.NoError(t, err)

	var decoded SecretFinding
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	assert.Equal(t, "projects/my-project/secrets/api-key", decoded.ResourceRef)
	assert.Equal(t, "Generic Secret", decoded.RuleName)
	assert.Equal(t, "generic-secret", decoded.RuleTextID)
	assert.Equal(t, "medium", decoded.Confidence)
	// Optional fields should be empty/zero values
	assert.Empty(t, decoded.Match)
	assert.Empty(t, decoded.FilePath)
	assert.Equal(t, 0, decoded.LineNumber)
}

// TestSecretFindingConfidenceLevels tests different confidence levels
func TestSecretFindingConfidenceLevels(t *testing.T) {
	confidenceLevels := []string{"low", "medium", "high", "critical"}

	for _, level := range confidenceLevels {
		finding := SecretFinding{
			ResourceRef: "test-resource",
			RuleName:    "Test Rule",
			RuleTextID:  "test-rule",
			Confidence:  level,
		}

		data, err := json.Marshal(finding)
		assert.NoError(t, err)

		var decoded SecretFinding
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)

		assert.Equal(t, level, decoded.Confidence)
	}
}

// TestRiskJSONSerialization tests that Risk can be marshaled and unmarshaled to/from JSON
func TestRiskJSONSerialization(t *testing.T) {
	target := &CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "arn:aws:s3:::vulnerable-bucket",
		AccountRef:   "123456789012",
		Region:       "us-east-1",
	}

	risk := Risk{
		Target:         target,
		Name:           "s3-bucket-public-access",
		DNS:            "123456789012",
		Status:         "TH",
		Source:         "aurelian-cdk-scanner",
		Description:    "S3 bucket allows public read access",
		Impact:         "Sensitive data may be exposed to unauthorized users",
		Recommendation: "Disable public access on the bucket",
		References:     "https://docs.aws.amazon.com/s3/security",
		Comment:        "Found during CDK bootstrap scan",
	}

	// Marshal to JSON
	data, err := json.Marshal(risk)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal back
	var decoded Risk
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	// Verify fields
	assert.Equal(t, "s3-bucket-public-access", decoded.Name)
	assert.Equal(t, "123456789012", decoded.DNS)
	assert.Equal(t, "TH", decoded.Status)
	assert.Equal(t, "aurelian-cdk-scanner", decoded.Source)
	assert.Equal(t, "S3 bucket allows public read access", decoded.Description)
	assert.Equal(t, "Sensitive data may be exposed to unauthorized users", decoded.Impact)
	assert.Equal(t, "Disable public access on the bucket", decoded.Recommendation)
	assert.Equal(t, "https://docs.aws.amazon.com/s3/security", decoded.References)
	assert.Equal(t, "Found during CDK bootstrap scan", decoded.Comment)

	// Verify Target resource
	assert.NotNil(t, decoded.Target)
	assert.Equal(t, "aws", decoded.Target.Platform)
	assert.Equal(t, "AWS::S3::Bucket", decoded.Target.ResourceType)
	assert.Equal(t, "arn:aws:s3:::vulnerable-bucket", decoded.Target.ResourceID)
}

// TestRiskMinimal tests minimal required fields
func TestRiskMinimal(t *testing.T) {
	target := &CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::Role",
		ResourceID:   "arn:aws:iam::123456789012:role/test-role",
		AccountRef:   "123456789012",
	}

	risk := Risk{
		Target:         target,
		Name:           "iam-role-overprivileged",
		DNS:            "123456789012",
		Status:         "TM",
		Source:         "apollo-iam-analysis",
		Description:    "IAM role has admin permissions",
		Impact:         "Role can perform any action in the account",
		Recommendation: "Apply principle of least privilege",
		References:     "https://docs.aws.amazon.com/iam/best-practices",
	}

	data, err := json.Marshal(risk)
	assert.NoError(t, err)

	var decoded Risk
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	assert.Equal(t, "iam-role-overprivileged", decoded.Name)
	assert.Equal(t, "TM", decoded.Status)
	// Comment is optional, should be empty
	assert.Empty(t, decoded.Comment)
}

// TestRiskSeverityLevels tests different severity levels
func TestRiskSeverityLevels(t *testing.T) {
	severityLevels := []string{"TL", "TM", "TH", "TC"}

	for _, severity := range severityLevels {
		target := &CloudResource{
			Platform:     "aws",
			ResourceType: "AWS::Lambda::Function",
			ResourceID:   "arn:aws:lambda:us-west-2:123456789012:function:test",
			AccountRef:   "123456789012",
		}

		risk := Risk{
			Target:         target,
			Name:           "test-risk",
			DNS:            "123456789012",
			Status:         severity,
			Source:         "test-scanner",
			Description:    "Test risk",
			Impact:         "Test impact",
			Recommendation: "Test recommendation",
			References:     "https://example.com",
		}

		data, err := json.Marshal(risk)
		assert.NoError(t, err)

		var decoded Risk
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)

		assert.Equal(t, severity, decoded.Status)
	}
}

// TestRiskWithNilTarget tests Risk with nil Target (edge case)
func TestRiskWithNilTarget(t *testing.T) {
	risk := Risk{
		Target:         nil,
		Name:           "general-security-issue",
		DNS:            "organization-123",
		Status:         "TL",
		Source:         "general-scanner",
		Description:    "General security recommendation",
		Impact:         "Informational",
		Recommendation: "Review security posture",
		References:     "https://example.com",
	}

	data, err := json.Marshal(risk)
	assert.NoError(t, err)

	var decoded Risk
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	assert.Nil(t, decoded.Target)
	assert.Equal(t, "general-security-issue", decoded.Name)
}
