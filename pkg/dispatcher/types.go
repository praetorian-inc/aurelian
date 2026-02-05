package dispatcher

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ProcessFunc is the signature for resource processor functions.
// Each processor receives:
//   - ctx: cancellation and deadline control
//   - resource: the AWS resource to process
//   - opts: configuration options (AWS profile, region, etc.)
//   - resultCh: channel to send NPInput results
type ProcessFunc func(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *ProcessOptions,
	resultCh chan<- types.NpInput,
) error

// ProcessOptions holds configuration for resource processing
type ProcessOptions struct {
	// AWS configuration
	AWSProfile string
	Regions    []string
	CacheDir   string

	// CloudWatch Logs specific options
	MaxEvents    int  // Maximum number of log events to fetch (default: 10000)
	MaxStreams   int  // Maximum number of log streams to process (default: 10)
	NewestFirst  bool // Fetch newest events first (default: false)
}

// DefaultProcessOptions returns default processing options
func DefaultProcessOptions() *ProcessOptions {
	return &ProcessOptions{
		MaxEvents:   10000,
		MaxStreams:  10,
		NewestFirst: false,
	}
}
