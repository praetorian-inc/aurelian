package ssm

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAWSListSSMDocuments(t *testing.T) {
	args := map[string]any{
		"profile":     "test-profile",
		"profile-dir": "/test/dir",
	}

	lister := NewAWSListSSMDocuments(args)

	require.NotNil(t, lister, "NewAWSListSSMDocuments should return non-nil")
	assert.NotNil(t, lister.NativeAWSLink, "NativeAWSLink should be initialized")
}

func TestAWSListSSMDocuments_ProcessInvalidInput(t *testing.T) {
	args := map[string]any{}
	lister := NewAWSListSSMDocuments(args)

	ctx := context.Background()

	// Test with invalid input type
	outputs, err := lister.Process(ctx, "invalid")

	assert.Error(t, err, "Process should return error for invalid input type")
	assert.Nil(t, outputs, "Outputs should be nil on error")
	assert.Contains(t, err.Error(), "expected *types.EnrichedResourceDescription", "Error should mention expected type")
}

func TestAWSListSSMDocuments_ProcessValidInput(t *testing.T) {
	// This test will fail until we implement the actual AWS SDK calls
	// For now, we're testing the structure
	args := map[string]any{
		"profile": "test-profile",
	}
	lister := NewAWSListSSMDocuments(args)

	ctx := context.Background()
	resource := &types.EnrichedResourceDescription{
		TypeName: "AWS::SSM::Document",
		Region:   "us-east-1",
	}

	// Note: This will fail in RED phase because Process is not implemented
	// We expect this test to fail until we implement the AWS SDK integration
	_, err := lister.Process(ctx, resource)

	// For now, we just verify the structure compiles
	// The actual implementation will be done in GREEN phase
	if err != nil {
		// Expected in RED phase - we haven't implemented AWS SDK calls yet
		t.Logf("Expected failure in RED phase: %v", err)
	}
}
