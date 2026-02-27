package cloudcontrol

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type CloudControlLister struct {
	plugin.AWSCommonRecon
	CrossRegionActor *ratelimit.CrossRegionActor
	AWSConfigs       map[string]*aws.Config
	configMu         sync.RWMutex
	accountID        string
	accountIDOnce    sync.Once
	accountIDErr     error
}

func NewCloudControlLister(options plugin.AWSCommonRecon) *CloudControlLister {
	if options.Concurrency <= 0 {
		options.Concurrency = 1
	}

	return &CloudControlLister{
		AWSCommonRecon:   options,
		CrossRegionActor: ratelimit.NewCrossRegionActor(options.Concurrency),
		AWSConfigs:       make(map[string]*aws.Config),
	}
}

// Enumerate resolves regions, handles single-resource mode (ResourceID), and
// builds a listing pipeline for the given supportedTypes. Returns a pipeline
// that emits AWSResource values.
func (cc *CloudControlLister) Enumerate(supportedTypes []string) (*pipeline.P[output.AWSResource], error) {
	resolved, err := awshelpers.ResolveRegions(cc.AWSCommonRecon.Regions, cc.Profile, cc.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("resolve regions: %w", err)
	}
	cc.AWSCommonRecon.Regions = resolved

	if cc.ResourceID != "" {
		resource, err := cc.fetchByARN(cc.ResourceID)
		if err != nil {
			return nil, fmt.Errorf("fetch resource %s: %w", cc.ResourceID, err)
		}
		return pipeline.From(resource), nil
	}

	resourceTypes, err := resolveResourceTypes(cc.AWSCommonRecon.ResourceType, supportedTypes)
	if err != nil {
		return nil, err
	}

	p1 := pipeline.From(resourceTypes...)
	p2 := pipeline.New[output.AWSResource]()
	pipeline.Pipe(p1, cc.List, p2)
	return p2, nil
}

// resolveResourceTypes validates requested types against supportedTypes.
// If requested is empty or ["all"], returns all supportedTypes.
func resolveResourceTypes(requested []string, supportedTypes []string) ([]string, error) {
	if len(requested) == 0 || (len(requested) == 1 && requested[0] == "all") {
		return supportedTypes, nil
	}

	for _, t := range requested {
		if !slices.Contains(supportedTypes, t) {
			return nil, fmt.Errorf("unsupported resource type %q; supported: %v", t, supportedTypes)
		}
	}
	return requested, nil
}

// fetchByARN parses an ARN and fetches the resource via CloudControl GetResource.
func (cc *CloudControlLister) fetchByARN(resourceARN string) (output.AWSResource, error) {
	erd, err := types.NewEnrichedResourceDescriptionFromArn(resourceARN)
	if err != nil {
		return output.AWSResource{}, fmt.Errorf("invalid ARN %q: %w", resourceARN, err)
	}

	return cc.GetResource(erd.Region, erd.TypeName, erd.Identifier)
}

// GetResource fetches a single resource by type and identifier, enriches it,
// and returns it directly. Used for single-resource evaluation mode.
func (cc *CloudControlLister) GetResource(region, resourceType, identifier string) (output.AWSResource, error) {
	client, err := cc.newCloudControlClient(region)
	if err != nil {
		return output.AWSResource{}, fmt.Errorf("create client: %w", err)
	}

	accountID, err := cc.getAccountID(region)
	if err != nil {
		return output.AWSResource{}, err
	}

	result, err := client.GetResource(context.Background(), &cloudcontrol.GetResourceInput{
		TypeName:   &resourceType,
		Identifier: &identifier,
	})
	if err != nil {
		return output.AWSResource{}, fmt.Errorf("get %s/%s: %w", resourceType, identifier, err)
	}

	cr := awshelpers.CloudControlToAWSResource(*result.ResourceDescription, resourceType, accountID, region)
	enrich := cc.generateEnricherMethod(region, resourceType)
	enrich(&cr)

	return cr, nil
}

// List enumerates a single resource type across all regions, emitting each
// resource into out as pages are fetched. Its signature matches the fn
// parameter of pipeline.Pipe[string, output.AWSResource].
func (cc *CloudControlLister) List(resourceType string, out *pipeline.P[output.AWSResource]) error {
	if len(cc.AWSCommonRecon.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	actor := ratelimit.NewCrossRegionActor(cc.Concurrency)
	return actor.ActInRegions(cc.AWSCommonRecon.Regions, func(region string) error {
		return cc.listInRegion(region, resourceType, out)
	})
}

func (cc *CloudControlLister) listInRegion(region, resourceType string, out *pipeline.P[output.AWSResource]) error {
	client, err := cc.newCloudControlClient(region)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	accountID, err := cc.getAccountID(region)
	if err != nil {
		return err
	}

	err = cc.listByType(client, accountID, region, resourceType, out)
	if cc.isSkippableError(err) {
		slog.Debug("skipping resource type", "type", resourceType, "region", region, "error", err)
		return nil
	} else if err != nil {
		slog.Warn("error listing resources", "type", resourceType, "region", region, "error", err)
		return err
	}

	return nil
}

func (cc *CloudControlLister) listByType(
	client *cloudcontrol.Client,
	accountID,
	region,
	resourceType string,
	out *pipeline.P[output.AWSResource],
) error {
	var nextToken *string

	enrich := cc.generateEnricherMethod(region, resourceType)
	paginator := ratelimit.NewPaginator()

	return paginator.Paginate(func() (bool, error) {
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
			cr := awshelpers.CloudControlToAWSResource(desc, resourceType, accountID, region)
			enrich(&cr)
			out.Send(cr)
		}

		nextToken = result.NextToken
		return nextToken != nil, nil
	})
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

func (cc *CloudControlLister) generateEnricherMethod(region, resourceType string) func(resource *output.AWSResource) {
	enrichers := plugin.GetEnrichers(resourceType)
	if len(enrichers) == 0 {
		return func(_ *output.AWSResource) {} // no-op
	}

	awsCfg, err := cc.getAWSConfig(region)
	if err != nil {
		slog.Warn("failed to fetch AWS config for enricher", "region", region, "type", resourceType, "error", err)
		return func(_ *output.AWSResource) {}
	}

	enrichCfg := plugin.EnricherConfig{
		Context:   context.Background(),
		AWSConfig: *awsCfg,
	}

	return func(resource *output.AWSResource) {
		for _, enrichFn := range enrichers {
			if err := enrichFn(enrichCfg, resource); err != nil {
				slog.Warn("enricher failed", "type", resourceType, "resource", resource.ResourceID, "error", err)
			}
		}
	}
}

func (cc *CloudControlLister) getAccountID(region string) (string, error) {
	cc.accountIDOnce.Do(func() {
		awsCfg, err := cc.getAWSConfig(region)
		if err != nil {
			cc.accountIDErr = err
			return
		}
		cc.accountID, cc.accountIDErr = awshelpers.GetAccountId(*awsCfg)
	})
	return cc.accountID, cc.accountIDErr
}

func (cc *CloudControlLister) getAWSConfig(region string) (*aws.Config, error) {
	cc.configMu.RLock()
	if cfg, ok := cc.AWSConfigs[region]; ok {
		cc.configMu.RUnlock()
		return cfg, nil
	}
	cc.configMu.RUnlock()

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    cc.Profile,
		ProfileDir: cc.ProfileDir,
	})
	if err != nil {
		return nil, err
	}

	cc.configMu.Lock()
	cc.AWSConfigs[region] = &awsCfg
	cc.configMu.Unlock()

	return &awsCfg, nil
}
