package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/dispatcher"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
)

// resetDispatcherRegistry is a test helper to reset the global dispatcher registry
func resetDispatcherRegistry() {
	// Access the private registry via reflection is not possible,
	// so we'll work with the public API
	// Tests will register their own processors as needed
}

// mockProcessor creates a mock processor that records calls
type mockProcessor struct {
	mu        sync.Mutex
	calls     []mockCall
	err       error
	sleepTime time.Duration
}

type mockCall struct {
	resourceType string
	identifier   string
}

func (m *mockProcessor) process(ctx context.Context, r *types.EnrichedResourceDescription, opts *dispatcher.ProcessOptions, resultCh chan<- types.NpInput) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{
		resourceType: r.TypeName,
		identifier:   r.Identifier,
	})
	m.mu.Unlock()

	if m.sleepTime > 0 {
		time.Sleep(m.sleepTime)
	}

	if m.err != nil {
		return m.err
	}

	// Send a mock result
	select {
	case resultCh <- types.NpInput{
		Content: "mock-secret",
		Provenance: types.NpProvenance{
			Platform:     "aws",
			ResourceType: r.TypeName,
			ResourceID:   r.Identifier,
		},
	}:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (m *mockProcessor) getCalls() []mockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]mockCall, len(m.calls))
	copy(result, m.calls)
	return result
}

func TestProcessAWSSecrets_EmptyInput(t *testing.T) {
	ctx := context.Background()
	resourceCh := make(chan *types.EnrichedResourceDescription)
	resultCh := make(chan types.NpInput, 10)

	// Close input channel immediately (empty input)
	close(resourceCh)

	err := ProcessAWSSecrets(ctx, resourceCh, resultCh)
	assert.NoError(t, err, "Empty input should not return error")

	close(resultCh)

	// Verify no results were produced
	results := collectResults(resultCh)
	assert.Empty(t, results, "Empty input should produce no results")
}

func TestProcessAWSSecrets_SingleResource(t *testing.T) {
	ctx := context.Background()
	resourceCh := make(chan *types.EnrichedResourceDescription, 1)
	resultCh := make(chan types.NpInput, 10)

	// Create mock processor
	mock := &mockProcessor{}
	dispatcher.RegisterAWSSecretProcessor("AWS::Test::SingleResource", mock.process)

	// Send one resource
	resource := &types.EnrichedResourceDescription{
		Identifier: "test-resource-1",
		TypeName:   "AWS::Test::SingleResource",
		Region:     "us-east-1",
		AccountId:  "123456789012",
		Arn: arn.ARN{
			Partition: "aws",
			Service:   "test",
			Region:    "us-east-1",
			AccountID: "123456789012",
			Resource:  "test-resource-1",
		},
	}
	resourceCh <- resource
	close(resourceCh)

	err := ProcessAWSSecrets(ctx, resourceCh, resultCh)
	assert.NoError(t, err, "Single resource processing should not error")

	close(resultCh)

	// Verify processor was called
	calls := mock.getCalls()
	assert.Len(t, calls, 1, "Processor should be called once")
	assert.Equal(t, "AWS::Test::SingleResource", calls[0].resourceType)
	assert.Equal(t, "test-resource-1", calls[0].identifier)

	// Verify result was produced
	results := collectResults(resultCh)
	assert.Len(t, results, 1, "Should have one result")
}

func TestProcessAWSSecrets_MultipleResources(t *testing.T) {
	ctx := context.Background()
	resourceCh := make(chan *types.EnrichedResourceDescription, 5)
	resultCh := make(chan types.NpInput, 20)

	// Create mock processor
	mock := &mockProcessor{}
	dispatcher.RegisterAWSSecretProcessor("AWS::Test::MultiResource", mock.process)

	// Send multiple resources
	for i := 0; i < 5; i++ {
		resource := &types.EnrichedResourceDescription{
			Identifier: fmt.Sprintf("test-resource-%d", i),
			TypeName:   "AWS::Test::MultiResource",
			Region:     "us-east-1",
			AccountId:  "123456789012",
			Arn: arn.ARN{
				Partition: "aws",
				Service:   "test",
				Region:    "us-east-1",
				AccountID: "123456789012",
				Resource:  fmt.Sprintf("test-resource-%d", i),
			},
		}
		resourceCh <- resource
	}
	close(resourceCh)

	err := ProcessAWSSecrets(ctx, resourceCh, resultCh)
	assert.NoError(t, err, "Multiple resource processing should not error")

	close(resultCh)

	// Verify processor was called for each resource
	calls := mock.getCalls()
	assert.Len(t, calls, 5, "Processor should be called 5 times")

	// Verify results were produced
	results := collectResults(resultCh)
	assert.Len(t, results, 5, "Should have 5 results")
}

func TestProcessAWSSecrets_UnregisteredResourceType(t *testing.T) {
	ctx := context.Background()
	resourceCh := make(chan *types.EnrichedResourceDescription, 1)
	resultCh := make(chan types.NpInput, 10)

	// Send resource with unregistered type
	resource := &types.EnrichedResourceDescription{
		Identifier: "unknown-resource",
		TypeName:   "AWS::Unknown::Type",
		Region:     "us-east-1",
		AccountId:  "123456789012",
		Arn: arn.ARN{
			Partition: "aws",
			Service:   "unknown",
			Region:    "us-east-1",
			AccountID: "123456789012",
			Resource:  "unknown-resource",
		},
	}
	resourceCh <- resource
	close(resourceCh)

	err := ProcessAWSSecrets(ctx, resourceCh, resultCh)
	assert.NoError(t, err, "Unregistered resource type should not error (silently skipped)")

	close(resultCh)

	// Verify no results were produced
	results := collectResults(resultCh)
	assert.Empty(t, results, "Unregistered type should produce no results")
}

func TestProcessAWSSecrets_ProcessorError(t *testing.T) {
	ctx := context.Background()
	resourceCh := make(chan *types.EnrichedResourceDescription, 1)
	resultCh := make(chan types.NpInput, 10)

	// Create mock processor that returns error
	mock := &mockProcessor{
		err: errors.New("processor failed"),
	}
	dispatcher.RegisterAWSSecretProcessor("AWS::Test::ErrorResource", mock.process)

	// Send resource
	resource := &types.EnrichedResourceDescription{
		Identifier: "error-resource",
		TypeName:   "AWS::Test::ErrorResource",
		Region:     "us-east-1",
		AccountId:  "123456789012",
		Arn: arn.ARN{
			Partition: "aws",
			Service:   "test",
			Region:    "us-east-1",
			AccountID: "123456789012",
			Resource:  "error-resource",
		},
	}
	resourceCh <- resource
	close(resourceCh)

	err := ProcessAWSSecrets(ctx, resourceCh, resultCh)
	assert.Error(t, err, "Processor error should be propagated")
	assert.Contains(t, err.Error(), "processor failed")
	assert.Contains(t, err.Error(), "AWS::Test::ErrorResource")
	assert.Contains(t, err.Error(), "error-resource")

	close(resultCh)
}

func TestProcessAWSSecrets_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	resourceCh := make(chan *types.EnrichedResourceDescription, 10)
	resultCh := make(chan types.NpInput, 20)

	// Create slow processor
	mock := &mockProcessor{
		sleepTime: 100 * time.Millisecond,
	}
	dispatcher.RegisterAWSSecretProcessor("AWS::Test::SlowResource", mock.process)

	// Send multiple resources
	for i := 0; i < 10; i++ {
		resource := &types.EnrichedResourceDescription{
			Identifier: fmt.Sprintf("slow-resource-%d", i),
			TypeName:   "AWS::Test::SlowResource",
			Region:     "us-east-1",
			AccountId:  "123456789012",
			Arn: arn.ARN{
				Partition: "aws",
				Service:   "test",
				Region:    "us-east-1",
				AccountID: "123456789012",
				Resource:  fmt.Sprintf("slow-resource-%d", i),
			},
		}
		resourceCh <- resource
	}
	close(resourceCh)

	// Cancel context after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := ProcessAWSSecrets(ctx, resourceCh, resultCh)

	// Should get context canceled error
	assert.Error(t, err, "Context cancellation should return error")
	assert.ErrorIs(t, err, context.Canceled, "Error should be context.Canceled")

	close(resultCh)
}

func TestProcessAWSSecrets_BoundedConcurrency(t *testing.T) {
	ctx := context.Background()
	resourceCh := make(chan *types.EnrichedResourceDescription, 20)
	resultCh := make(chan types.NpInput, 100)

	// Create processor that tracks concurrent calls
	var concurrentCalls int32
	var maxConcurrent int32
	var mu sync.Mutex

	processFunc := func(ctx context.Context, r *types.EnrichedResourceDescription, opts *dispatcher.ProcessOptions, resultCh chan<- types.NpInput) error {
		mu.Lock()
		concurrentCalls++
		if concurrentCalls > maxConcurrent {
			maxConcurrent = concurrentCalls
		}
		mu.Unlock()

		// Simulate work
		time.Sleep(10 * time.Millisecond)

		mu.Lock()
		concurrentCalls--
		mu.Unlock()

		return nil
	}

	dispatcher.RegisterAWSSecretProcessor("AWS::Test::ConcurrentResource", processFunc)

	// Send 20 resources
	for i := 0; i < 20; i++ {
		resource := &types.EnrichedResourceDescription{
			Identifier: fmt.Sprintf("concurrent-resource-%d", i),
			TypeName:   "AWS::Test::ConcurrentResource",
			Region:     "us-east-1",
			AccountId:  "123456789012",
			Arn: arn.ARN{
				Partition: "aws",
				Service:   "test",
				Region:    "us-east-1",
				AccountID: "123456789012",
				Resource:  fmt.Sprintf("concurrent-resource-%d", i),
			},
		}
		resourceCh <- resource
	}
	close(resourceCh)

	// Process with limit of 5
	err := ProcessAWSSecrets(ctx, resourceCh, resultCh, WithConcurrencyLimit(5))
	assert.NoError(t, err)

	close(resultCh)

	// Verify concurrency was bounded
	mu.Lock()
	actualMax := maxConcurrent
	mu.Unlock()

	assert.LessOrEqual(t, actualMax, int32(5), "Concurrent calls should not exceed limit")
	assert.Greater(t, actualMax, int32(1), "Should have some concurrency")
}

func TestProcessAWSSecrets_WithProcessOptions(t *testing.T) {
	ctx := context.Background()
	resourceCh := make(chan *types.EnrichedResourceDescription, 1)
	resultCh := make(chan types.NpInput, 10)

	// Create processor that checks options
	var capturedOpts *dispatcher.ProcessOptions
	processFunc := func(ctx context.Context, r *types.EnrichedResourceDescription, opts *dispatcher.ProcessOptions, resultCh chan<- types.NpInput) error {
		capturedOpts = opts
		return nil
	}

	dispatcher.RegisterAWSSecretProcessor("AWS::Test::OptionsResource", processFunc)

	// Send resource
	resource := &types.EnrichedResourceDescription{
		Identifier: "options-resource",
		TypeName:   "AWS::Test::OptionsResource",
		Region:     "us-east-1",
		AccountId:  "123456789012",
		Arn: arn.ARN{
			Partition: "aws",
			Service:   "test",
			Region:    "us-east-1",
			AccountID: "123456789012",
			Resource:  "options-resource",
		},
	}
	resourceCh <- resource
	close(resourceCh)

	// Custom options
	customOpts := &dispatcher.ProcessOptions{
		AWSProfile: "custom-profile",
		Regions:    []string{"us-west-2"},
		MaxEvents:  5000,
	}

	err := ProcessAWSSecrets(ctx, resourceCh, resultCh, WithProcessOptions(customOpts))
	assert.NoError(t, err)

	close(resultCh)

	// Verify options were passed through
	assert.NotNil(t, capturedOpts)
	assert.Equal(t, "custom-profile", capturedOpts.AWSProfile)
	assert.Equal(t, []string{"us-west-2"}, capturedOpts.Regions)
	assert.Equal(t, 5000, capturedOpts.MaxEvents)
}

// Helper function to collect all results from a channel
func collectResults(ch <-chan types.NpInput) []types.NpInput {
	var results []types.NpInput
	for r := range ch {
		results = append(results, r)
	}
	return results
}
