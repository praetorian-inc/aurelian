package recon

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/dispatcher"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// FindAWSSecretsResourceV2 is the refactored version using plain Go patterns
// instead of janus-framework chains. It processes a single AWS resource specified by ARN.
type FindAWSSecretsResourceV2 struct {
	Profile     string
	ResourceARN string

	// CloudWatch Logs options (same as v2)
	MaxEvents   int
	MaxStreams  int
	NewestFirst bool
}

// NewFindAWSSecretsResourceV2 creates a new v2 single-resource secret finder with sensible defaults.
func NewFindAWSSecretsResourceV2(profile, resourceARN string) *FindAWSSecretsResourceV2 {
	return &FindAWSSecretsResourceV2{
		Profile:     profile,
		ResourceARN: resourceARN,
		MaxEvents:   10000,
		MaxStreams:  10,
		NewestFirst: false,
	}
}

// Run executes the AWS secrets finding workflow for a single resource.
// Returns the secrets found as NpInput objects.
func (f *FindAWSSecretsResourceV2) Run(ctx context.Context) ([]types.NpInput, error) {
	// 1. Parse ARN to EnrichedResourceDescription
	erd, err := types.NewEnrichedResourceDescriptionFromArn(f.ResourceARN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse resource ARN %s: %w", f.ResourceARN, err)
	}

	// 2. Get processor for this resource type
	processor := dispatcher.GetAWSSecretProcessor(erd.TypeName)
	if processor == nil {
		return nil, fmt.Errorf("unsupported resource type: %s", erd.TypeName)
	}

	// 3. Create result channel
	resultCh := make(chan types.NpInput, 100)

	// 4. Collect results in background
	var results []types.NpInput
	done := make(chan struct{})
	go func() {
		defer close(done)
		for result := range resultCh {
			results = append(results, result)
		}
	}()

	// 5. Process the single resource
	opts := &dispatcher.ProcessOptions{
		AWSProfile:  f.Profile,
		Regions:     []string{erd.Region},
		MaxEvents:   f.MaxEvents,
		MaxStreams:  f.MaxStreams,
		NewestFirst: f.NewestFirst,
	}

	if err := processor(ctx, &erd, opts, resultCh); err != nil {
		close(resultCh)
		return nil, fmt.Errorf("failed to process resource %s: %w", f.ResourceARN, err)
	}

	// 6. Close result channel and wait for collection
	close(resultCh)
	<-done

	return results, nil
}
