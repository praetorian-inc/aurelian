package recon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewFindAWSSecretsV2 tests that the constructor creates a properly initialized instance
func TestNewFindAWSSecretsV2(t *testing.T) {
	profile := "test-profile"
	regions := []string{"us-east-1", "us-west-2"}

	finder := NewFindAWSSecretsV2(profile, regions)

	require.NotNil(t, finder)
	assert.Equal(t, profile, finder.Profile)
	assert.Equal(t, regions, finder.Regions)
	assert.Equal(t, 10000, finder.MaxEvents, "MaxEvents should default to 10000")
	assert.Equal(t, 10, finder.MaxStreams, "MaxStreams should default to 10")
	assert.False(t, finder.NewestFirst, "NewestFirst should default to false")
	assert.NotEmpty(t, finder.ResourceTypes, "ResourceTypes should be populated from dispatcher")
}

// TestFindAWSSecretsV2_HandleCloudControlError tests error handling logic
func TestFindAWSSecretsV2_HandleCloudControlError(t *testing.T) {
	finder := &FindAWSSecretsV2{}

	tests := []struct {
		name           string
		errMsg         string
		expectedSkip   bool
		expectedReason string
	}{
		{
			name:           "TypeNotFoundException should skip",
			errMsg:         "TypeNotFoundException: Resource type not found",
			expectedSkip:   true,
			expectedReason: "resource type not available",
		},
		{
			name:           "UnsupportedActionException should skip",
			errMsg:         "UnsupportedActionException: Action not supported",
			expectedSkip:   true,
			expectedReason: "resource type not available",
		},
		{
			name:           "AccessDeniedException should skip",
			errMsg:         "AccessDeniedException: User is not authorized",
			expectedSkip:   true,
			expectedReason: "resource type not available",
		},
		{
			name:           "is not authorized should skip",
			errMsg:         "User is not authorized to perform this action",
			expectedSkip:   true,
			expectedReason: "resource type not available",
		},
		{
			name:           "ThrottlingException should continue",
			errMsg:         "ThrottlingException: Rate exceeded",
			expectedSkip:   false,
			expectedReason: "should retry after rate limit",
		},
		{
			name:           "Unknown error should continue",
			errMsg:         "InternalError: Something went wrong",
			expectedSkip:   false,
			expectedReason: "unknown errors should propagate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake error with the test message
			err := &fakeError{msg: tt.errMsg}

			shouldSkip := finder.handleCloudControlError("AWS::EC2::Instance", "us-east-1", err)

			assert.Equal(t, tt.expectedSkip, shouldSkip, tt.expectedReason)
		})
	}
}

// TestFindAWSSecretsV2_IsGlobalService tests global service detection
func TestFindAWSSecretsV2_IsGlobalService(t *testing.T) {
	finder := &FindAWSSecretsV2{}

	tests := []struct {
		name         string
		resourceType string
		region       string
		isGlobal     bool
	}{
		{
			name:         "IAM in us-east-1 is not skipped",
			resourceType: "AWS::IAM::Role",
			region:       "us-east-1",
			isGlobal:     false,
		},
		{
			name:         "IAM in us-west-2 should be skipped",
			resourceType: "AWS::IAM::Role",
			region:       "us-west-2",
			isGlobal:     true,
		},
		{
			name:         "EC2 in us-west-2 is regional",
			resourceType: "AWS::EC2::Instance",
			region:       "us-west-2",
			isGlobal:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := finder.isGlobalService(tt.resourceType, tt.region)
			assert.Equal(t, tt.isGlobal, result)
		})
	}
}

// fakeError is a simple error implementation for testing
type fakeError struct {
	msg string
}

func (e *fakeError) Error() string {
	return e.msg
}

// TestFindAWSSecretsV2_Run_Integration is an integration test that requires AWS credentials
// It is skipped in CI/CD environments
func TestFindAWSSecretsV2_Run_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This test would require actual AWS credentials and should be run manually
	t.Skip("Integration test - requires AWS credentials")

	ctx := context.Background()
	finder := NewFindAWSSecretsV2("default", []string{"us-east-1"})
	finder.ResourceTypes = []string{"AWS::S3::Bucket"} // Limit to one resource type for testing

	results, err := finder.Run(ctx)
	require.NoError(t, err)

	// Just verify we can run without errors - actual results depend on AWS account state
	assert.NotNil(t, results)
}
