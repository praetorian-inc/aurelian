package helpers

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCloudControlToAWSResource_NilIdentifier verifies that a ResourceDescription
// with a nil Identifier — an AWS Cloud Control API contract violation — is
// reported as invalid (ok == false) so callers can skip emitting it, rather than
// producing a phantom zero-value resource that flows to output.
func TestCloudControlToAWSResource_NilIdentifier(t *testing.T) {
	desc := cctypes.ResourceDescription{
		Identifier: nil,
		Properties: aws.String(`{"Name":"ignored"}`),
	}

	resource, ok := CloudControlToAWSResource(desc, "AWS::Lambda::Function", "123456789012", "us-east-1")

	assert.False(t, ok, "nil Identifier must report ok=false so the caller skips the send")
	assert.Equal(t, "", resource.ResourceID, "no resource should be constructed for a nil Identifier")
	assert.Equal(t, "", resource.ResourceType, "no resource should be constructed for a nil Identifier")
}

// TestCloudControlToAWSResource_NilProperties verifies that a nil Properties —
// a normal, expected condition for resource types that return no property blob —
// produces a valid resource (ok == true) with an empty Properties map and does
// not panic.
func TestCloudControlToAWSResource_NilProperties(t *testing.T) {
	desc := cctypes.ResourceDescription{
		Identifier: aws.String("my-func"),
		Properties: nil,
	}

	resource, ok := CloudControlToAWSResource(desc, "AWS::Lambda::Function", "123456789012", "us-east-1")

	require.True(t, ok, "nil Properties is normal data; the resource must still be valid")
	assert.Equal(t, "my-func", resource.ResourceID)
	assert.Equal(t, "AWS::Lambda::Function", resource.ResourceType)
	assert.NotNil(t, resource.Properties, "Properties should be a non-nil empty map, not nil")
	assert.Empty(t, resource.Properties, "Properties should be empty when the source is nil")
}

// TestCloudControlToAWSResource_ValidJSONProperties verifies the happy path:
// a populated Identifier and valid JSON Properties yield a fully-formed resource.
func TestCloudControlToAWSResource_ValidJSONProperties(t *testing.T) {
	desc := cctypes.ResourceDescription{
		Identifier: aws.String("my-func"),
		Properties: aws.String(`{"FunctionName":"my-func","Runtime":"go1.x"}`),
	}

	resource, ok := CloudControlToAWSResource(desc, "AWS::Lambda::Function", "123456789012", "us-east-1")

	require.True(t, ok)
	assert.Equal(t, "my-func", resource.ResourceID)
	assert.Equal(t, "AWS::Lambda::Function", resource.ResourceType)
	assert.Equal(t, "123456789012", resource.AccountRef)
	assert.Equal(t, "us-east-1", resource.Region)
	assert.Equal(t, "my-func", resource.Properties["FunctionName"])
	assert.Equal(t, "go1.x", resource.Properties["Runtime"])
}

// TestCloudControlToAWSResource_InvalidJSONProperties verifies that
// non-JSON Properties are preserved under the raw_properties key rather than
// being dropped, and the resource is still valid.
func TestCloudControlToAWSResource_InvalidJSONProperties(t *testing.T) {
	desc := cctypes.ResourceDescription{
		Identifier: aws.String("my-func"),
		Properties: aws.String("not-json"),
	}

	resource, ok := CloudControlToAWSResource(desc, "AWS::Lambda::Function", "123456789012", "us-east-1")

	require.True(t, ok)
	assert.Equal(t, "not-json", resource.Properties["raw_properties"])
}
