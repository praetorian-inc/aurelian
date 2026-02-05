package dispatcher

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
)

// resetRegistry is a test helper to reset the global registry between tests
func resetRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()
	processorRegistry = make(map[string]ProcessFunc)
}

func TestRegisterAWSSecretProcessor(t *testing.T) {
	resetRegistry()

	// Create a test processor function
	testProcessor := func(ctx context.Context, r *types.EnrichedResourceDescription, opts *ProcessOptions, resultCh chan<- types.NpInput) error {
		return nil
	}

	// Register processor
	RegisterAWSSecretProcessor("AWS::Test::Type", testProcessor)

	// Verify registration
	processor := GetAWSSecretProcessor("AWS::Test::Type")
	assert.NotNil(t, processor, "Processor should be registered")
}

func TestRegisterAWSSecretProcessor_NilProcessor(t *testing.T) {
	resetRegistry()

	// Registering nil processor should panic
	assert.Panics(t, func() {
		RegisterAWSSecretProcessor("AWS::Test::Type", nil)
	}, "Registering nil processor should panic")
}

func TestRegisterAWSSecretProcessor_DuplicateRegistration(t *testing.T) {
	resetRegistry()

	testProcessor := func(ctx context.Context, r *types.EnrichedResourceDescription, opts *ProcessOptions, resultCh chan<- types.NpInput) error {
		return nil
	}

	// First registration should succeed
	RegisterAWSSecretProcessor("AWS::Test::Type", testProcessor)

	// Second registration of same type should panic
	assert.Panics(t, func() {
		RegisterAWSSecretProcessor("AWS::Test::Type", testProcessor)
	}, "Duplicate registration should panic")
}

func TestGetAWSSecretProcessor_NotFound(t *testing.T) {
	resetRegistry()

	// Get processor for non-existent type
	processor := GetAWSSecretProcessor("AWS::NonExistent::Type")
	assert.Nil(t, processor, "Non-existent processor should return nil")
}

func TestGetAWSSecretProcessor_Found(t *testing.T) {
	resetRegistry()

	testProcessor := func(ctx context.Context, r *types.EnrichedResourceDescription, opts *ProcessOptions, resultCh chan<- types.NpInput) error {
		return nil
	}

	RegisterAWSSecretProcessor("AWS::EC2::Instance", testProcessor)

	processor := GetAWSSecretProcessor("AWS::EC2::Instance")
	assert.NotNil(t, processor, "Registered processor should be found")
}

func TestSupportedAWSSecretTypes_Empty(t *testing.T) {
	resetRegistry()

	types := SupportedAWSSecretTypes()
	assert.Empty(t, types, "Empty registry should return empty slice")
}

func TestSupportedAWSSecretTypes_Multiple(t *testing.T) {
	resetRegistry()

	testProcessor := func(ctx context.Context, r *types.EnrichedResourceDescription, opts *ProcessOptions, resultCh chan<- types.NpInput) error {
		return nil
	}

	// Register multiple types
	RegisterAWSSecretProcessor("AWS::EC2::Instance", testProcessor)
	RegisterAWSSecretProcessor("AWS::S3::Bucket", testProcessor)
	RegisterAWSSecretProcessor("AWS::Lambda::Function", testProcessor)

	types := SupportedAWSSecretTypes()
	assert.Len(t, types, 3, "Should have 3 registered types")
	assert.Contains(t, types, "AWS::EC2::Instance")
	assert.Contains(t, types, "AWS::S3::Bucket")
	assert.Contains(t, types, "AWS::Lambda::Function")
}

func TestSupportedAWSSecretTypes_Order(t *testing.T) {
	resetRegistry()

	testProcessor := func(ctx context.Context, r *types.EnrichedResourceDescription, opts *ProcessOptions, resultCh chan<- types.NpInput) error {
		return nil
	}

	// Register in specific order
	RegisterAWSSecretProcessor("AWS::Type::A", testProcessor)
	RegisterAWSSecretProcessor("AWS::Type::B", testProcessor)
	RegisterAWSSecretProcessor("AWS::Type::C", testProcessor)

	types := SupportedAWSSecretTypes()
	assert.Len(t, types, 3, "Should have 3 registered types")
	// Note: map iteration order is not guaranteed, so we just check all are present
	assert.Contains(t, types, "AWS::Type::A")
	assert.Contains(t, types, "AWS::Type::B")
	assert.Contains(t, types, "AWS::Type::C")
}
