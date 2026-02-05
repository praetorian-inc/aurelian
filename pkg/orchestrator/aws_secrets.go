package orchestrator

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/dispatcher"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"golang.org/x/sync/errgroup"
)

// ProcessAWSSecrets orchestrates the processing of AWS resources to find secrets.
//
// This is the main entry point for the AWS find-secrets functionality. It:
//   1. Receives AWS resources via resourceCh channel
//   2. Dispatches each resource to its registered processor function
//   3. Uses bounded concurrency (errgroup with SetLimit) to control parallelism
//   4. Collects results into resultCh channel
//
// Parameters:
//   - ctx: cancellation and deadline control
//   - resourceCh: input channel streaming EnrichedResourceDescription objects
//   - resultCh: output channel for NPInput results (secrets found)
//   - opts: configuration options (functional options pattern)
//
// Returns error if any processor fails or context is cancelled.
//
// Example usage:
//
//	resultCh := make(chan types.NpInput, 100)
//	err := ProcessAWSSecrets(ctx, resourceCh, resultCh,
//	    WithConcurrencyLimit(25),
//	    WithProcessOptions(&dispatcher.ProcessOptions{
//	        AWSProfile: "my-profile",
//	        MaxEvents:  5000,
//	    }),
//	)
func ProcessAWSSecrets(
	ctx context.Context,
	resourceCh <-chan *types.EnrichedResourceDescription,
	resultCh chan<- types.NpInput,
	opts ...Option,
) error {
	cfg := applyOptions(opts)

	// Create errgroup with bounded concurrency
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(cfg.concurrencyLimit)

	// Process each resource from the input channel
	for resource := range resourceCh {
		resource := resource // Capture for goroutine

		// Check context before spawning new goroutine
		select {
		case <-gCtx.Done():
			return gCtx.Err()
		default:
		}

		g.Go(func() error {
			return processResource(gCtx, resource, cfg.processOpts, resultCh)
		})
	}

	// Wait for all processors to complete
	return g.Wait()
}

// processResource dispatches a single resource to its registered processor.
// Returns error if no processor is registered or if processing fails.
func processResource(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *dispatcher.ProcessOptions,
	resultCh chan<- types.NpInput,
) error {
	// Lookup processor function for this resource type
	processor := dispatcher.GetAWSSecretProcessor(resource.TypeName)
	if processor == nil {
		// Skip unsupported resource types silently
		// (This allows graceful handling of new resource types not yet implemented)
		return nil
	}

	// Execute processor function
	if err := processor(ctx, resource, opts, resultCh); err != nil {
		return fmt.Errorf("processing %s %s: %w",
			resource.TypeName,
			resource.Identifier,
			err,
		)
	}

	return nil
}
