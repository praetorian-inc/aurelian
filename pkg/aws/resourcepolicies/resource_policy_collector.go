package resourcepolicies

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// policyMethod is a method signature for fetching a resource policy.
type policyMethod func(ctx context.Context, cfg aws.Config, r *output.AWSResource) (*types.Policy, error)

// ResourcePolicyCollector collects resource policies for AWS resources.
type ResourcePolicyCollector struct {
	opts             plugin.AWSCommonRecon
	crossRegionActor *ratelimit.CrossRegionActor
}

// New creates a new ResourcePolicyCollector.
func New(opts plugin.AWSCommonRecon) *ResourcePolicyCollector {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	return &ResourcePolicyCollector{
		opts:             opts,
		crossRegionActor: ratelimit.NewCrossRegionActor(concurrency),
	}
}

// registry returns the map of resource types to their policy-fetching methods.
func (c *ResourcePolicyCollector) registry() map[string]policyMethod {
	return map[string]policyMethod{
		"AWS::S3::Bucket":                c.s3BucketPolicy,
		"AWS::Lambda::Function":          c.lambdaPolicy,
		"AWS::SNS::Topic":                c.snsTopicPolicy,
		"AWS::SQS::Queue":                c.sqsQueuePolicy,
		"AWS::EFS::FileSystem":           c.efsPolicy,
		"AWS::OpenSearchService::Domain": c.openSearchPolicy,
		"AWS::Elasticsearch::Domain":     c.elasticsearchPolicy,
	}
}

// SupportedResourceTypes returns the resource types this collector can fetch policies for.
func (c *ResourcePolicyCollector) SupportedResourceTypes() []string {
	reg := c.registry()
	out := make([]string, 0, len(reg))
	for rt := range reg {
		out = append(out, rt)
	}
	return out
}

// Collect fetches resource policies for all supported resources, grouped by region.
// Regions are processed concurrently using a CrossRegionActor for rate limiting.
// It returns only resources that have a policy, with Properties["ResourcePolicy"] populated.
func (c *ResourcePolicyCollector) Collect(resourcesByRegion map[string][]output.AWSResource) ([]output.AWSResource, error) {
	reg := c.registry()

	// Build the list of regions that have resources to process.
	var regions []string
	for region, resources := range resourcesByRegion {
		if len(resources) > 0 {
			regions = append(regions, region)
		}
	}

	if len(regions) == 0 {
		return nil, nil
	}

	var mu sync.Mutex
	var results []output.AWSResource

	err := c.crossRegionActor.ActInRegions(regions, func(region string) error {
		awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     region,
			Profile:    c.opts.Profile,
			ProfileDir: c.opts.ProfileDir,
		})
		if err != nil {
			slog.Warn("creating AWS config for resource policies, skipping region",
				"region", region, "error", err)
			return nil
		}

		regionResults, err := c.collectInRegion(reg, awsCfg, resourcesByRegion[region])
		if err != nil {
			return fmt.Errorf("region %s: %w", region, err)
		}

		mu.Lock()
		results = append(results, regionResults...)
		mu.Unlock()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}

// collectInRegion fetches policies for all supported resources in a single region.
func (c *ResourcePolicyCollector) collectInRegion(reg map[string]policyMethod, awsCfg aws.Config, resources []output.AWSResource) ([]output.AWSResource, error) {
	ctx := context.Background()
	var results []output.AWSResource

	for _, resource := range resources {
		method, ok := reg[resource.ResourceType]
		if !ok {
			continue
		}

		policy, err := method(ctx, awsCfg, &resource)
		if err != nil {
			slog.Warn("fetching resource policy, skipping resource",
				"resource", resource.ResourceID,
				"type", resource.ResourceType,
				"error", err)
			continue
		}

		if policy == nil {
			continue
		}

		resource.ResourcePolicy = policy
		results = append(results, resource)
	}

	return results, nil
}

// --- per-service methods (private) ---

func (c *ResourcePolicyCollector) s3BucketPolicy(ctx context.Context, cfg aws.Config, r *output.AWSResource) (*types.Policy, error) {
	client := s3.NewFromConfig(cfg)
	return FetchS3BucketPolicy(ctx, client, r)
}

func (c *ResourcePolicyCollector) lambdaPolicy(ctx context.Context, cfg aws.Config, r *output.AWSResource) (*types.Policy, error) {
	client := lambda.NewFromConfig(cfg)
	return FetchLambdaPolicy(ctx, client, r)
}

func (c *ResourcePolicyCollector) snsTopicPolicy(ctx context.Context, cfg aws.Config, r *output.AWSResource) (*types.Policy, error) {
	client := sns.NewFromConfig(cfg)
	return FetchSNSTopicPolicy(ctx, client, r)
}

func (c *ResourcePolicyCollector) sqsQueuePolicy(ctx context.Context, cfg aws.Config, r *output.AWSResource) (*types.Policy, error) {
	client := sqs.NewFromConfig(cfg)
	return FetchSQSQueuePolicy(ctx, client, r)
}

func (c *ResourcePolicyCollector) efsPolicy(ctx context.Context, cfg aws.Config, r *output.AWSResource) (*types.Policy, error) {
	client := efs.NewFromConfig(cfg)
	return FetchEFSPolicy(ctx, client, r)
}

func (c *ResourcePolicyCollector) openSearchPolicy(ctx context.Context, cfg aws.Config, r *output.AWSResource) (*types.Policy, error) {
	client := opensearch.NewFromConfig(cfg)
	return FetchOpenSearchPolicy(ctx, client, r)
}

func (c *ResourcePolicyCollector) elasticsearchPolicy(ctx context.Context, cfg aws.Config, r *output.AWSResource) (*types.Policy, error) {
	client := elasticsearchservice.NewFromConfig(cfg)
	return FetchElasticsearchPolicy(ctx, client, r)
}
