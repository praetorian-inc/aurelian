package stages

import (
	"context"
	"sync"

	"github.com/praetorian-inc/nebula/pkg/templates"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func AzureARGEnrichStage(ctx context.Context, opts []*types.Option, in <-chan *templates.ARGQueryResult) <-chan *templates.ARGQueryResult {
	out := make(chan *templates.ARGQueryResult)

	// Start a goroutine to handle the parallel processing
	go func() {
		defer close(out)

		// Create a worker pool to process results in parallel
		const maxWorkers = 10 // Limit concurrent goroutines
		semaphore := make(chan struct{}, maxWorkers)
		var wg sync.WaitGroup

		for result := range in {
			// Check if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Acquire semaphore slot
			semaphore <- struct{}{}
			wg.Add(1)

			// Process this result in a goroutine
			go func(r *templates.ARGQueryResult) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore slot

				// Add commands to the result based on template type
				switch r.TemplateID {
				case "storage_accounts_public_access":
					r.Commands = enrichStorageAccount(ctx, r)
				}

				// Send the enriched result to output channel
				select {
				case out <- r:
				case <-ctx.Done():
					return
				}
			}(result)
		}

		// Wait for all goroutines to complete
		wg.Wait()
	}()

	return out
}
