package cloudcontrol

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"golang.org/x/sync/errgroup"
)

type clientFactory func(ctx context.Context, region string) (*cloudcontrol.Client, string, aws.Config, error)

type ListAllOptions struct {
	ResourceTypes []string
	Regions       []string
	Concurrency   int
	Profile       string
	ProfileDir    string
}

func ListAll(ctx context.Context, opts ListAllOptions) (map[string][]output.CloudResource, error) {
	factory := func(ctx context.Context, region string) (*cloudcontrol.Client, string, aws.Config, error) {
		awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     region,
			Profile:    opts.Profile,
			ProfileDir: opts.ProfileDir,
		})
		if err != nil {
			return nil, "", aws.Config{}, err
		}
		accountID, _ := awshelpers.GetAccountId(awsCfg)
		client := cloudcontrol.NewFromConfig(awsCfg)
		return client, accountID, awsCfg, nil
	}
	return listAll(ctx, factory, opts)
}

func listAll(ctx context.Context, factory clientFactory, opts ListAllOptions) (map[string][]output.CloudResource, error) {
	limiter := ratelimit.NewAWSRegionLimiter(opts.Concurrency)
	results := make(map[string][]output.CloudResource)
	var mu sync.Mutex

	g := errgroup.Group{}
	g.SetLimit(opts.Concurrency)

	for _, region := range opts.Regions {
		region := region // Capture loop variable
		g.Go(func() error {
			release, err := limiter.Acquire(ctx, region)
			if err != nil {
				return err
			}
			defer release()

			client, accountID, awsCfg, err := factory(ctx, region)
			if err != nil {
				return fmt.Errorf("region %s: create client: %w", region, err)
			}

			regionResults, err := listRegion(ctx, client, limiter, accountID, region, opts.ResourceTypes, opts.Concurrency, awsCfg)
			if err != nil {
				return fmt.Errorf("region %s: %w", region, err)
			}

			mu.Lock()
			for key, records := range regionResults {
				results[key] = append(results[key], records...)
			}
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}

func listRegion(
	ctx context.Context,
	client *cloudcontrol.Client,
	limiter *ratelimit.AWSRegionLimiter,
	accountID, region string,
	resourceTypes []string,
	concurrency int,
	awsCfg aws.Config,
) (map[string][]output.CloudResource, error) {
	results := make(map[string][]output.CloudResource)
	var mu sync.Mutex

	g := errgroup.Group{}
	g.SetLimit(concurrency)

	for _, resourceType := range resourceTypes {
		resourceType := resourceType // Capture loop variable
		g.Go(func() error {
			// Acquire rate limit token for this type enumeration
			release, err := limiter.Acquire(ctx, region)
			if err != nil {
				return err
			}
			defer release()

			resources, err := ListByType(ctx, client, resourceType, accountID, region)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if IsSkippableError(err) {
					slog.Debug("skipping resource type", "type", resourceType, "region", region, "error", err)
					return nil
				}
				slog.Warn("error listing resources", "type", resourceType, "region", region, "error", err)
				return nil
			}

			// Apply registered enrichers
			enrichers := plugin.GetEnrichers(resourceType)
			for i := range resources {
				enrichCfg := plugin.EnricherConfig{
					Context:   ctx,
					AWSConfig: awsCfg,
				}
				for _, enrich := range enrichers {
					if err := enrich(enrichCfg, &resources[i]); err != nil {
						slog.Warn("enricher failed",
							"type", resourceType,
							"resource", resources[i].ResourceID,
							"error", err,
						)
					}
				}
			}

			// Use region/resourceType format for keys
			key := fmt.Sprintf("%s/%s", region, resourceType)
			mu.Lock()
			results[key] = resources
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

	backoffWait := 5 * time.Second
	maxAttempts := 5
	retryAttempt := 0

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
			if strings.Contains(err.Error(), "ThrottlingException: Rate exceeded") && retryAttempt < maxAttempts {
				time.Sleep(backoffWait * time.Duration(math.Pow(2, float64(retryAttempt))))
				retryAttempt++
				continue
			}

			return nil, fmt.Errorf("list %s: %w", resourceType, err)
		}

		retryAttempt = 0

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

func IsSkippableError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "TypeNotFoundException") ||
		strings.Contains(s, "UnsupportedActionException") ||
		strings.Contains(s, "AccessDeniedException")
}
