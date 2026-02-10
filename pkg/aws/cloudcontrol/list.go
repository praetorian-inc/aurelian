package cloudcontrol

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"golang.org/x/sync/errgroup"
)

// ListAll enumerates multiple resource types concurrently with rate limiting.
// Uses best-effort enumeration: skippable errors (access denied, unsupported types)
// are logged and skipped. Only context cancellation propagates as an error.
func ListAll(ctx context.Context, client *cloudcontrol.Client, resourceTypes []string, accountID, region string, concurrency int) (map[string][]output.CloudResource, error) {
	results := make(map[string][]output.CloudResource)
	var mu sync.Mutex

	limiter := ratelimit.NewAWSRegionLimiter(concurrency)

	g := errgroup.Group{}
	g.SetLimit(concurrency)

	for _, rt := range resourceTypes {
		g.Go(func() error {
			release, err := limiter.Acquire(ctx, region)
			if err != nil {
				return err
			}
			defer release()

			resources, err := ListByType(ctx, client, rt, accountID, region)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if IsSkippableError(err) {
					slog.Debug("skipping resource type", "type", rt, "error", err)
					return nil
				}
				slog.Warn("error listing resources", "type", rt, "error", err)
				return nil
			}

			mu.Lock()
			results[rt] = resources
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}

// ListByType enumerates all resources of a specific type with pagination.
func ListByType(ctx context.Context, client *cloudcontrol.Client, resourceType, accountID, region string) ([]output.CloudResource, error) {
	var all []output.CloudResource
	var nextToken *string

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		input := &cloudcontrol.ListResourcesInput{
			TypeName: &resourceType,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		result, err := client.ListResources(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", resourceType, err)
		}

		for _, desc := range result.ResourceDescriptions {
			cr := helpers.CloudControlToERD(desc, resourceType, accountID, region).ToCloudResource()
			all = append(all, cr)
		}

		nextToken = result.NextToken
		if nextToken == nil {
			break
		}
	}

	return all, nil
}

// IsSkippableError returns true for CloudControl errors that should be logged
// and skipped rather than treated as fatal (e.g., unsupported types, access denied).
func IsSkippableError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "TypeNotFoundException") ||
		strings.Contains(s, "UnsupportedActionException") ||
		strings.Contains(s, "AccessDeniedException")
}
