package resourcepolicies

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

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
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// policyMethod is a method signature for fetching a resource policy.
type policyMethod func(ctx context.Context, cfg aws.Config, r *output.AWSResource) (*types.Policy, error)

// ResourcePolicyCollector collects resource policies for AWS resources.
type ResourcePolicyCollector struct {
	profile    string
	profileDir string
}

// New creates a new ResourcePolicyCollector.
func New(profile, profileDir string) *ResourcePolicyCollector {
	return &ResourcePolicyCollector{
		profile:    profile,
		profileDir: profileDir,
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
// It returns only resources that have a policy, with Properties["ResourcePolicy"] populated.
// Region-level errors are non-fatal (logged and skipped), matching the original graph module behavior.
func (c *ResourcePolicyCollector) Collect(resourcesByRegion map[string][]output.AWSResource) ([]output.AWSResource, error) {
	ctx := context.Background()
	reg := c.registry()

	var results []output.AWSResource

	for region, resources := range resourcesByRegion {
		if len(resources) == 0 {
			continue
		}

		awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     region,
			Profile:    c.profile,
			ProfileDir: c.profileDir,
		})
		if err != nil {
			slog.Warn("creating AWS config for resource policies, skipping region",
				"region", region, "error", err)
			continue
		}

		for _, resource := range resources {
			method, ok := reg[resource.ResourceType]
			if !ok {
				continue
			}

			policy, err := method(ctx, awsCfg, &resource)
			if err != nil {
				return nil, fmt.Errorf("fetch policy for %s (%s): %w",
					resource.ResourceID, resource.ResourceType, err)
			}

			if policy == nil {
				continue
			}

			policyJSON, err := json.Marshal(policy)
			if err != nil {
				return nil, fmt.Errorf("marshal policy for %s: %w", resource.ResourceID, err)
			}
			resource.Properties["ResourcePolicy"] = string(policyJSON)
			results = append(results, resource)
		}
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


