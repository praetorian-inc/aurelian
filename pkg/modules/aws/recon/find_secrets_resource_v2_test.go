package recon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewFindAWSSecretsResourceV2 tests that the constructor creates a properly initialized instance
func TestNewFindAWSSecretsResourceV2(t *testing.T) {
	profile := "test-profile"
	resourceARN := "arn:aws:lambda:us-east-1:123456789012:function:my-function"

	finder := NewFindAWSSecretsResourceV2(profile, resourceARN)

	require.NotNil(t, finder)
	assert.Equal(t, profile, finder.Profile)
	assert.Equal(t, resourceARN, finder.ResourceARN)
	assert.Equal(t, 10000, finder.MaxEvents, "MaxEvents should default to 10000")
	assert.Equal(t, 10, finder.MaxStreams, "MaxStreams should default to 10")
	assert.False(t, finder.NewestFirst, "NewestFirst should default to false")
}

// TestFindAWSSecretsResourceV2_InvalidARN tests Run() handles invalid ARN gracefully
func TestFindAWSSecretsResourceV2_InvalidARN(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		resourceARN string
		expectError string
	}{
		{
			name:        "Empty ARN",
			resourceARN: "",
			expectError: "failed to parse resource ARN",
		},
		{
			name:        "Malformed ARN - missing colons",
			resourceARN: "not-an-arn",
			expectError: "failed to parse resource ARN",
		},
		{
			name:        "Malformed ARN - invalid format",
			resourceARN: "arn:invalid:format",
			expectError: "failed to parse resource ARN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := NewFindAWSSecretsResourceV2("test-profile", tt.resourceARN)

			results, err := finder.Run(ctx)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
			assert.Nil(t, results)
		})
	}
}

// TestFindAWSSecretsResourceV2_UnsupportedResourceType tests Run() handles unsupported types
func TestFindAWSSecretsResourceV2_UnsupportedResourceType(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		resourceARN string
		expectError string
	}{
		{
			name:        "Unknown service",
			resourceARN: "arn:aws:unknown:us-east-1:123456789012:resource/name",
			expectError: "unsupported resource type",
		},
		{
			name:        "Valid ARN but no dispatcher",
			resourceARN: "arn:aws:unsupported:us-west-2:123456789012:resource/test",
			expectError: "unsupported resource type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := NewFindAWSSecretsResourceV2("test-profile", tt.resourceARN)

			results, err := finder.Run(ctx)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
			assert.Nil(t, results)
		})
	}
}

// TestFindAWSSecretsResourceV2_ValidARNParsing tests ARN parsing for various resource types
func TestFindAWSSecretsResourceV2_ValidARNParsing(t *testing.T) {
	tests := []struct {
		name         string
		resourceARN  string
		expectedType string
	}{
		{
			name:         "Lambda ARN",
			resourceARN:  "arn:aws:lambda:us-east-1:123456789012:function:my-function",
			expectedType: "AWS::Lambda::Function",
		},
		{
			name:         "S3 ARN",
			resourceARN:  "arn:aws:s3:::my-bucket",
			expectedType: "AWS::S3::Bucket",
		},
		{
			name:         "EC2 ARN",
			resourceARN:  "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
			expectedType: "AWS::EC2::Instance",
		},
		{
			name:         "IAM Role ARN",
			resourceARN:  "arn:aws:iam::123456789012:role/MyRole",
			expectedType: "AWS::IAM::Role",
		},
		{
			name:         "DynamoDB Table ARN",
			resourceARN:  "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable",
			expectedType: "AWS::DynamoDB::Table",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := NewFindAWSSecretsResourceV2("test-profile", tt.resourceARN)

			// Test that ARN is stored correctly
			assert.Equal(t, tt.resourceARN, finder.ResourceARN)

			// Verify Profile is stored
			assert.Equal(t, "test-profile", finder.Profile)

			// Note: We don't call Run() here because it requires AWS credentials
			// and actual processors. ARN parsing is tested via the types package.
		})
	}
}

// TestFindAWSSecretsResourceV2_DefaultValues verifies all default values
func TestFindAWSSecretsResourceV2_DefaultValues(t *testing.T) {
	finder := NewFindAWSSecretsResourceV2("profile", "arn:aws:s3:::bucket")

	// Verify all CloudWatch Logs options have correct defaults
	assert.Equal(t, 10000, finder.MaxEvents, "MaxEvents default")
	assert.Equal(t, 10, finder.MaxStreams, "MaxStreams default")
	assert.False(t, finder.NewestFirst, "NewestFirst default")
}

// TestFindAWSSecretsResourceV2_CustomOptions tests that custom options can be set
func TestFindAWSSecretsResourceV2_CustomOptions(t *testing.T) {
	finder := NewFindAWSSecretsResourceV2("profile", "arn:aws:s3:::bucket")

	// Modify options
	finder.MaxEvents = 5000
	finder.MaxStreams = 20
	finder.NewestFirst = true

	assert.Equal(t, 5000, finder.MaxEvents)
	assert.Equal(t, 20, finder.MaxStreams)
	assert.True(t, finder.NewestFirst)
}

// TestFindAWSSecretsResourceV2_Run_Integration is an integration test that requires AWS credentials
// It is skipped in CI/CD environments
func TestFindAWSSecretsResourceV2_Run_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This test would require actual AWS credentials and should be run manually
	t.Skip("Integration test - requires AWS credentials and dispatcher processors")

	ctx := context.Background()
	finder := NewFindAWSSecretsResourceV2("default", "arn:aws:s3:::test-bucket")

	results, err := finder.Run(ctx)
	require.NoError(t, err)

	// Just verify we can run without errors - actual results depend on AWS account state
	assert.NotNil(t, results)
}
