package publicaccess

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPropertyBasedTypeClassification(t *testing.T) {
	assert.True(t, propertyBasedTypes["AWS::EC2::Instance"])
	assert.True(t, propertyBasedTypes["AWS::Cognito::UserPool"])
	assert.True(t, propertyBasedTypes["AWS::RDS::DBInstance"])
	assert.False(t, propertyBasedTypes["AWS::S3::Bucket"])
	assert.False(t, propertyBasedTypes["AWS::Lambda::Function"])
}

func TestPolicyBasedTypeClassification(t *testing.T) {
	assert.True(t, policyBasedTypes["AWS::S3::Bucket"])
	assert.True(t, policyBasedTypes["AWS::SNS::Topic"])
	assert.True(t, policyBasedTypes["AWS::SQS::Queue"])
	assert.True(t, policyBasedTypes["AWS::Lambda::Function"])
	assert.True(t, policyBasedTypes["AWS::EFS::FileSystem"])
	assert.False(t, policyBasedTypes["AWS::EC2::Instance"])
	assert.False(t, policyBasedTypes["AWS::RDS::DBInstance"])
}

func TestCheckPropertyAccess_EC2WithPublicIP(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Properties: map[string]any{
			"PublicIpAddress": "54.123.45.67",
		},
	}

	result := checkPropertyAccess(resource)
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.True(t, result.NeedsManualTriage)
	assert.Contains(t, result.AllowedActions, "ec2:NetworkAccess")
}

func TestCheckPropertyAccess_EC2WithoutPublicIP(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Properties:   map[string]any{},
	}

	result := checkPropertyAccess(resource)
	assert.Nil(t, result)
}

func TestCheckPropertyAccess_RDSPublic(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "mydb",
		Properties: map[string]any{
			"IsPubliclyAccessible": true,
		},
	}

	result := checkPropertyAccess(resource)
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.False(t, result.NeedsManualTriage)
}

func TestCheckPropertyAccess_RDSNotPublic(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "mydb",
		Properties: map[string]any{
			"IsPubliclyAccessible": false,
		},
	}

	result := checkPropertyAccess(resource)
	assert.Nil(t, result)
}

func TestCheckPropertyAccess_CognitoSelfSignup(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abc123",
		Properties: map[string]any{
			"SelfSignupEnabled": true,
		},
	}

	result := checkPropertyAccess(resource)
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
}

func TestCheckPropertyAccess_CognitoNoSelfSignup(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abc123",
		Properties: map[string]any{
			"SelfSignupEnabled": false,
		},
	}

	result := checkPropertyAccess(resource)
	assert.Nil(t, result)
}

func TestCheckPropertyAccess_UnsupportedType(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "my-bucket",
		Properties:   map[string]any{},
	}

	result := checkPropertyAccess(resource)
	assert.Nil(t, result)
}

func TestSetResult(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-123",
		Properties:   map[string]any{},
	}

	result := &PublicAccessResult{
		IsPublic:          true,
		NeedsManualTriage: true,
		AllowedActions:    []string{"ec2:NetworkAccess"},
		EvaluationReasons: []string{"has public IP"},
	}

	setResult(resource, result)

	_, ok := resource.Properties["PublicAccessResult"]
	assert.True(t, ok, "PublicAccessResult should be set in properties")
}
