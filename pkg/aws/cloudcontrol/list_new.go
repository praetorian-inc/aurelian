package cloudcontrol

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

type CloudControlLister struct {
	AWSCommonRecon
	CrossRegionActor *ratelimit.CrossRegionActor
	AWSConfigs       map[string]*aws.Config
}

func NewCloudControlLister(concurrency int, profile, profileDir string) *CloudControlLister {
	if concurrency <= 0 {
		concurrency = 1
	}

	return &CloudControlLister{
		Concurrency:      concurrency,
		Profile:          profile,
		ProfileDir:       profileDir,
		CrossRegionActor: ratelimit.NewCrossRegionActor(concurrency),
		AWSConfigs:       make(map[string]*aws.Config),
	}
}

func (cc *CloudControlLister) List(regions, resourceTypes []string) (map[string][]output.CloudResource, error) {
	if len(regions) == 0 || len(resourceTypes) == 0 {
		return map[string][]output.CloudResource{}, nil
	}

	results := make(map[string][]output.CloudResource)
	var mu sync.Mutex

	actor := ratelimit.NewCrossRegionActor(cc.Concurrency)
	err := actor.ActInRegions(regions, func(region string) error {
		regionResources, err := cc.ListInRegion(region, resourceTypes...)
		if err != nil {
			return fmt.Errorf("region %s: %w", region, err)
		}

		mu.Lock()
		defer mu.Unlock()

		for _, resource := range regionResources {
			key := fmt.Sprintf("%s/%s", region, resource.ResourceType)
			results[key] = append(results[key], resource)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (cc *CloudControlLister) ListInRegion(region string, resourceTypes ...string) ([]output.CloudResource, error) {
	if len(resourceTypes) == 0 {
		return nil, nil
	}

	client, err := cc.newCloudControlClient(region)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	accountID, err := cc.getAccountID(region)
	if err != nil {
		return nil, err
	}

	var all []output.CloudResource
	for _, resourceType := range resourceTypes {
		resources, err := cc.listByType(client, accountID, region, resourceType)

		if cc.isSkippableError(err) {
			slog.Debug("skipping resource type", "type", resourceType, "region", region, "error", err)
			continue
		} else if err != nil {
			slog.Warn("error listing resources", "type", resourceType, "region", region, "error", err)
			return nil, err
		}

		all = append(all, resources...)
	}

	return all, nil
}

func (cc *CloudControlLister) isSkippableError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "TypeNotFoundException") ||
		strings.Contains(s, "UnsupportedActionException") ||
		strings.Contains(s, "AccessDeniedException")
}

func (cc *CloudControlLister) newCloudControlClient(region string) (*cloudcontrol.Client, error) {
	awsCfg, err := cc.getAWSConfig(region)
	if err != nil {
		return nil, err
	}
	return cloudcontrol.NewFromConfig(*awsCfg), nil
}

func (cc *CloudControlLister) listByType(client *cloudcontrol.Client, accountID, region, resourceType string) ([]output.CloudResource, error) {
	var all []output.CloudResource
	var nextToken *string

	enrich := cc.generateEnricherMethod(region, resourceType)
	paginator := ratelimit.NewPaginator()

	err := paginator.Paginate(func() (bool, error) {
		input := &cloudcontrol.ListResourcesInput{
			TypeName: &resourceType,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		result, err := client.ListResources(context.Background(), input)
		if err != nil {
			return true, fmt.Errorf("list %s: %w", resourceType, err)
		}

		for _, desc := range result.ResourceDescriptions {
			cr := helpers.CloudControlToERD(desc, resourceType, accountID, region).ToCloudResource()
			enrich(&cr)
			all = append(all, cr)
		}

		nextToken = result.NextToken
		return nextToken != nil, nil
	})
	if err != nil {
		return nil, err
	}

	return all, nil
}

func (cc *CloudControlLister) generateEnricherMethod(region, resourceType string) func(resource *output.CloudResource) {
	enrichers := plugin.GetEnrichers(resourceType)
	if len(enrichers) == 0 {
		return func(_ *output.CloudResource) {} // no-op
	}

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
				slog.Warn("enricher failed", "type", resourceType, "resource", resource.ResourceID, "error", err)
			}
		}
	}
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

func (cc *CloudControlLister) getAWSConfig(region string) (*aws.Config, error) {
	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    cc.Profile,
		ProfileDir: cc.ProfileDir,
	})
	if err != nil {
		return nil, err
	}

	return &awsCfg, nil
}
