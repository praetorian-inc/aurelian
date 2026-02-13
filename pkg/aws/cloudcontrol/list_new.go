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

type CloudControlLister struct {
	Concurrency int
	Profile     string
	ProfileDir  string
	Limiters    map[string]*ratelimit.AWSRegionLimiter
	AWSConfigs  map[string]*aws.Config
	mu          sync.RWMutex
}

func NewCloudControlLister(concurrency int, profile, profileDir string) *CloudControlLister {
	return &CloudControlLister{
		Concurrency: concurrency,
		Profile:     profile,
		ProfileDir:  profileDir,
		Limiters:    make(map[string]*ratelimit.AWSRegionLimiter),
		AWSConfigs:  make(map[string]*aws.Config),
	}
}

func (cc *CloudControlLister) List(regions, resourceTypes []string) (map[string][]output.CloudResource, error) {
	if len(regions) == 0 || len(resourceTypes) == 0 {
		return map[string][]output.CloudResource{}, nil
	}

	limit := cc.concurrencyOrDefault()
	if cc.Limiters == nil {
		cc.Limiters = make(map[string]*ratelimit.AWSRegionLimiter)
	}
	for _, region := range regions {
		if _, ok := cc.Limiters[region]; !ok {
			cc.Limiters[region] = ratelimit.NewAWSRegionLimiter(limit)
		}
	}

	results := make(map[string][]output.CloudResource)
	var mu sync.Mutex

	g := errgroup.Group{}
	g.SetLimit(limit)

	for _, region := range regions {
		region := region
		g.Go(func() error {
			limiter := cc.Limiters[region]
			release, err := limiter.Acquire(context.Background(), region)
			if err != nil {
				return err
			}
			defer release()

			client, err := cc.newClient(region)
			if err != nil {
				return fmt.Errorf("region %s: create client: %w", region, err)
			}

			regionResources, err := cc.ListInRegion(client, region, resourceTypes...)
			if err != nil {
				return fmt.Errorf("region %s: %w", region, err)
			}

			mu.Lock()
			for _, resource := range regionResources {
				key := fmt.Sprintf("%s/%s", region, resource.ResourceType)
				results[key] = append(results[key], resource)
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

func (cc *CloudControlLister) ListInRegion(client *cloudcontrol.Client, region string, resourceTypes ...string) ([]output.CloudResource, error) {
	if len(resourceTypes) == 0 {
		return nil, nil
	}

	accountID, err := cc.getAccountID(region)
	if err != nil {
		return nil, err
	}

	var all []output.CloudResource
	for _, resourceType := range resourceTypes {
		resources, err := cc.listByType(client, accountID, region, resourceType)
		if err != nil {
			if IsSkippableError(err) {
				slog.Debug("skipping resource type", "type", resourceType, "region", region, "error", err)
				continue
			}
			slog.Warn("error listing resources", "type", resourceType, "region", region, "error", err)
			return nil, err
		}
		all = append(all, resources...)
	}

	return all, nil
}

func (cc *CloudControlLister) newClient(region string) (*cloudcontrol.Client, error) {
	awsCfg, err := cc.getAWSConfig(region)
	if err != nil {
		return nil, err
	}
	return cloudcontrol.NewFromConfig(*awsCfg), nil
}

func (cc *CloudControlLister) listByType(client *cloudcontrol.Client, accountID, region, resourceType string) ([]output.CloudResource, error) {
	var all []output.CloudResource
	var nextToken *string

	backoffWait := 5 * time.Second
	maxAttempts := 5
	retryAttempt := 0
	enrichers := plugin.GetEnrichers(resourceType)
	enrich := func(_ *output.CloudResource) {}
	if len(enrichers) > 0 {
		enrich = cc.generateEnricherMethod(region, resourceType, enrichers)
	}

	for {
		input := &cloudcontrol.ListResourcesInput{
			TypeName: &resourceType,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		result, err := client.ListResources(context.Background(), input)
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
			enrich(&cr)
			all = append(all, cr)
		}

		nextToken = result.NextToken
		if nextToken == nil {
			break
		}
	}

	return all, nil
}

func (cc *CloudControlLister) generateEnricherMethod(region, resourceType string, enrichers []plugin.EnricherFunc) func(resource *output.CloudResource) {
	awsCfg, err := cc.getAWSConfig(region)
	if err != nil {
		slog.Warn("failed to fetch AWS config for enricher", "region", region, "type", resourceType, "error", err)
		return func(_ *output.CloudResource) {}
	}

	enrichCfg := plugin.EnricherConfig{
		Context:   context.Background(),
		AWSConfig: *awsCfg,
	}
	return func(resource *output.CloudResource) {
		for _, enrichFn := range enrichers {
			if err := enrichFn(enrichCfg, resource); err != nil {
				slog.Warn("enricher failed",
					"type", resourceType,
					"resource", resource.ResourceID,
					"error", err,
				)
			}
		}
	}
}

func (cc *CloudControlLister) getAWSConfig(region string) (*aws.Config, error) {
	cc.mu.RLock()
	if awsCfg, ok := cc.AWSConfigs[region]; ok {
		cc.mu.RUnlock()
		return awsCfg, nil
	}
	cc.mu.RUnlock()

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    cc.Profile,
		ProfileDir: cc.ProfileDir,
	})
	if err != nil {
		return nil, err
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()
	if existing, ok := cc.AWSConfigs[region]; ok {
		return existing, nil
	}
	cc.AWSConfigs[region] = &awsCfg
	return &awsCfg, nil
}

func (cc *CloudControlLister) getAccountID(region string) (string, error) {
	awsCfg, err := cc.getAWSConfig(region)
	if err != nil {
		return "", err
	}
	accountID, err := awshelpers.GetAccountId(*awsCfg)
	if err != nil {
		return "", err
	}
	return accountID, nil
}

func (cc *CloudControlLister) concurrencyOrDefault() int {
	if cc.Concurrency <= 0 {
		return 1
	}
	return cc.Concurrency
}
