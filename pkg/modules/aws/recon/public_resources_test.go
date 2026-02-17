package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/publicaccess"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicResourcesModuleMetadata(t *testing.T) {
	m := &AWSPublicResourcesModule{}

	assert.Equal(t, "public-resources", m.ID())
	assert.Equal(t, "AWS Public Resources", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())

	authors := m.Authors()
	require.Len(t, authors, 1)
	assert.Equal(t, "Praetorian", authors[0])

	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
}

func TestPublicResourcesSupportedResourceTypes(t *testing.T) {
	m := &AWSPublicResourcesModule{}
	types := m.SupportedResourceTypes()

	expected := []string{
		"AWS::EC2::Instance",
		"AWS::S3::Bucket",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::Lambda::Function",
		"AWS::EFS::FileSystem",
		"AWS::Cognito::UserPool",
		"AWS::RDS::DBInstance",
	}

	assert.Equal(t, expected, types)
	assert.Len(t, types, 8)
}

func TestPublicResourcesParameters(t *testing.T) {
	m := &AWSPublicResourcesModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	// Must include AWS params from AWSCommonRecon
	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["regions"], "should have regions param")
	assert.True(t, paramNames["concurrency"], "should have concurrency param")

	// Must include org-policies param
	assert.True(t, paramNames["org-policies"], "should have org-policies param")
}

func TestPropertyBasedTypeClassification(t *testing.T) {
	// Verify property-based types
	assert.True(t, propertyBasedTypes["AWS::EC2::Instance"])
	assert.True(t, propertyBasedTypes["AWS::Cognito::UserPool"])
	assert.True(t, propertyBasedTypes["AWS::RDS::DBInstance"])
	assert.False(t, propertyBasedTypes["AWS::S3::Bucket"])
	assert.False(t, propertyBasedTypes["AWS::Lambda::Function"])
}

func TestPolicyBasedTypeClassification(t *testing.T) {
	// Verify policy-based types
	assert.True(t, policyBasedTypes["AWS::S3::Bucket"])
	assert.True(t, policyBasedTypes["AWS::SNS::Topic"])
	assert.True(t, policyBasedTypes["AWS::SQS::Queue"])
	assert.True(t, policyBasedTypes["AWS::Lambda::Function"])
	assert.True(t, policyBasedTypes["AWS::EFS::FileSystem"])
	assert.False(t, policyBasedTypes["AWS::EC2::Instance"])
	assert.False(t, policyBasedTypes["AWS::RDS::DBInstance"])
}

func TestCheckPropertyBasedAccess_EC2WithPublicIP(t *testing.T) {
	resource := &output.CloudResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Properties: map[string]any{
			"PublicIpAddress": "54.123.45.67",
		},
	}

	result := checkPropertyBasedAccess(resource)
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.True(t, result.NeedsManualTriage)
	assert.Contains(t, result.AllowedActions, "ec2:NetworkAccess")
}

func TestCheckPropertyBasedAccess_EC2WithoutPublicIP(t *testing.T) {
	resource := &output.CloudResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Properties:   map[string]any{},
	}

	result := checkPropertyBasedAccess(resource)
	assert.Nil(t, result)
}

func TestCheckPropertyBasedAccess_RDSPublic(t *testing.T) {
	resource := &output.CloudResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "mydb",
		Properties: map[string]any{
			"IsPubliclyAccessible": true,
		},
	}

	result := checkPropertyBasedAccess(resource)
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
	assert.False(t, result.NeedsManualTriage)
}

func TestCheckPropertyBasedAccess_RDSNotPublic(t *testing.T) {
	resource := &output.CloudResource{
		ResourceType: "AWS::RDS::DBInstance",
		ResourceID:   "mydb",
		Properties: map[string]any{
			"IsPubliclyAccessible": false,
		},
	}

	result := checkPropertyBasedAccess(resource)
	assert.Nil(t, result)
}

func TestCheckPropertyBasedAccess_CognitoSelfSignup(t *testing.T) {
	resource := &output.CloudResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abc123",
		Properties: map[string]any{
			"SelfSignupEnabled": true,
		},
	}

	result := checkPropertyBasedAccess(resource)
	require.NotNil(t, result)
	assert.True(t, result.IsPublic)
}

func TestCheckPropertyBasedAccess_CognitoNoSelfSignup(t *testing.T) {
	resource := &output.CloudResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   "us-east-1_abc123",
		Properties: map[string]any{
			"SelfSignupEnabled": false,
		},
	}

	result := checkPropertyBasedAccess(resource)
	assert.Nil(t, result)
}

func TestCheckPropertyBasedAccess_UnsupportedType(t *testing.T) {
	resource := &output.CloudResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "my-bucket",
		Properties:   map[string]any{},
	}

	result := checkPropertyBasedAccess(resource)
	assert.Nil(t, result)
}

func TestSetPublicAccessResult(t *testing.T) {
	resource := &output.CloudResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-123",
		Properties:   map[string]any{},
	}

	result := &publicaccess.PublicAccessResult{
		IsPublic:          true,
		NeedsManualTriage: true,
		AllowedActions:    []string{"ec2:NetworkAccess"},
		EvaluationReasons: []string{"has public IP"},
	}

	setPublicAccessResult(resource, result)

	_, ok := resource.Properties["PublicAccessResult"]
	assert.True(t, ok, "PublicAccessResult should be set in properties")
}
