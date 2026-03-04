package output

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAWSResourceJSONSerialization tests that AWSResource can be marshaled and unmarshaled to/from JSON
func TestAWSResourceJSONSerialization(t *testing.T) {
	resource := AWSResource{
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
	var decoded AWSResource
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	// Verify fields
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

// TestAWSResourceMinimal tests minimal required fields
func TestAWSResourceMinimal(t *testing.T) {
	resource := AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		AccountRef:   "123456789012",
	}

	data, err := json.Marshal(resource)
	assert.NoError(t, err)

	var decoded AWSResource
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

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

func TestAWSResourceAccessLevelJSONSerialization(t *testing.T) {
	resource := AWSResource{ResourceType: "AWS::S3::Bucket", ResourceID: "x", AccountRef: "123", AccessLevel: AccessLevelPublic}
	data, err := json.Marshal(resource)
	assert.NoError(t, err)
	assert.Contains(t, string(data), `"access_level":"public"`)
}
