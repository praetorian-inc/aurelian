package recon

import (
	"context"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"golang.org/x/sync/errgroup"
)

// gatherResourcePolicies fetches resource-based policies for AWS resources with bounded concurrency.
// Returns a map of resource ARN to policy document.
// TODO: Implement full resource policy fetching for Lambda, S3, etc. Currently returns empty map.
func (a *ApolloV2) gatherResourcePolicies(ctx context.Context, resources []types.EnrichedResourceDescription) (map[string]*types.Policy, error) {
	policies := make(map[string]*types.Policy)
	var mu sync.Mutex

	// Use errgroup with bounded concurrency
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(25) // Bounded concurrency limit

	for _, resource := range resources {
		resource := resource // Capture for goroutine

		g.Go(func() error {
			// Check context cancellation
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}

			// Fetch resource policy
			policy, err := a.fetchResourcePolicy(gCtx, &resource)
			if err != nil {
				// Log but don't fail - some resources have no policy or fetching is not yet implemented
				return nil
			}

			if policy != nil {
				mu.Lock()
				policies[resource.Arn.String()] = policy
				mu.Unlock()
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return policies, nil
}

// fetchResourcePolicy fetches the resource-based policy for a single AWS resource.
// TODO: Implement per-resource-type policy fetching (Lambda, S3, etc.).
// Currently returns nil (no policy) for all resource types.
func (a *ApolloV2) fetchResourcePolicy(ctx context.Context, resource *types.EnrichedResourceDescription) (*types.Policy, error) {
	// Placeholder implementation
	// Full implementation would switch on resource.TypeName and call appropriate SDK:
	// - AWS::Lambda::Function -> lambda.GetPolicy()
	// - AWS::S3::Bucket -> s3.GetBucketPolicy()
	// - AWS::SQS::Queue -> sqs.GetQueueAttributes()
	// - etc.

	// For now, return nil (no policy) which is valid for resources without policies
	return nil, nil
}
