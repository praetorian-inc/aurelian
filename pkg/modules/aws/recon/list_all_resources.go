package recon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"golang.org/x/sync/errgroup"
)

func init() {
	plugin.Register(&AWSListAllResourcesModule{})
}

// AWSListAllResourcesModule enumerates all resources using Cloud Control API
type AWSListAllResourcesModule struct{}

func (m *AWSListAllResourcesModule) ID() string                   { return "list-all" }
func (m *AWSListAllResourcesModule) Name() string                 { return "AWS List All Resources" }
func (m *AWSListAllResourcesModule) Platform() plugin.Platform    { return plugin.PlatformAWS }
func (m *AWSListAllResourcesModule) Category() plugin.Category    { return plugin.CategoryRecon }
func (m *AWSListAllResourcesModule) OpsecLevel() string           { return "moderate" }
func (m *AWSListAllResourcesModule) Authors() []string            { return []string{"Praetorian"} }

func (m *AWSListAllResourcesModule) Description() string {
	return "List resources in an AWS account using CloudControl API. Supports 'full' scan for all resources or 'summary' scan for key services."
}

func (m *AWSListAllResourcesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/Welcome.html",
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSListAllResourcesModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("scan-type", "Scan type - 'full' for all resources or 'summary' for key services",
			plugin.WithDefault("full"),
			plugin.WithShortcode("s"),
			plugin.WithEnum("full", "summary"),
		),
		plugin.NewParam[string]("region", "AWS region",
			plugin.WithDefault("us-east-1"),
		),
		options.AwsProfile(),
		options.AwsProfileDir(),
		plugin.NewParam[int]("concurrency", "Maximum concurrent CloudControl API requests",
			plugin.WithDefault(5),
		),
	}
}

func (m *AWSListAllResourcesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	params := plugin.NewParameters(m.Parameters()...)

	// Apply runtime args from Config (backward compat with current CLI generator)
	for k, v := range cfg.Args {
		params.Set(k, v)
	}

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("parameter validation failed: %w", err)
	}

	scanType := params.String("scan-type")
	region := params.String("region")
	profile := params.String("profile")
	profileDir := params.String("profile-dir")
	concurrency := params.Int("concurrency")

	// Build opts slice for GetAWSCfg
	var opts []*types.Option
	if profileDir != "" {
		opts = append(opts, &types.Option{
			Name:  "profile-dir",
			Value: profileDir,
		})
	}

	awsCfg, err := helpers.GetAWSCfg(region, profile, opts, "moderate")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	accountID, err := helpers.GetAccountId(awsCfg)
	if err != nil {
		accountID = ""
	}

	// Get resource types to enumerate
	var resourceTypes []string
	if strings.ToLower(scanType) == "summary" {
		resourceTypes = keySummaryResourceTypes()
	} else {
		resourceTypes = allResourceTypes()
	}

	// Create CloudControl client
	client := cloudcontrol.NewFromConfig(awsCfg)

	// Create enumerator
	enumerator := &ResourceEnumerator{
		Client:        client,
		AccountID:     accountID,
		Region:        region,
		Concurrency:   concurrency,
		ResourceTypes: resourceTypes,
	}

	// Enumerate resources
	results, err := enumerator.Enumerate(cfg.Context)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate resources: %w", err)
	}

	return []plugin.Result{
		{
			Data: results,
			Metadata: map[string]any{
				"module":      "list-all",
				"platform":    "aws",
				"opsec_level": "moderate",
			},
		},
	}, nil
}

// CloudControlLister defines the interface for CloudControl API operations
type CloudControlLister interface {
	ListResources(ctx context.Context, input *cloudcontrol.ListResourcesInput, opts ...func(*cloudcontrol.Options)) (*cloudcontrol.ListResourcesOutput, error)
}

// ResourceEnumerator handles concurrent resource enumeration with rate limiting
type ResourceEnumerator struct {
	Client        CloudControlLister
	AccountID     string
	Region        string
	Concurrency   int
	ResourceTypes []string
}

// Enumerate lists all resources concurrently with rate limiting.
// Uses best-effort enumeration: skippable errors are logged, not propagated.
func (e *ResourceEnumerator) Enumerate(ctx context.Context) (map[string][]output.CloudResource, error) {
	results := make(map[string][]output.CloudResource)
	var mu sync.Mutex

	// Create rate limiter per-module instance
	limiter := ratelimit.NewAWSRegionLimiter(e.Concurrency)

	// Bare errgroup: best-effort enumeration, errors don't cancel siblings
	g := errgroup.Group{}
	g.SetLimit(e.Concurrency)

	for _, resourceType := range e.ResourceTypes {
		g.Go(func() error {
			// Acquire rate limit token (blocks until slot available or context cancelled)
			release, err := limiter.Acquire(ctx, e.Region)
			if err != nil {
				return err // context cancelled
			}
			defer release()

			// List resources for this type
			resources, err := e.listResourcesByType(ctx, resourceType)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}

				if isSkippableCloudControlError(err) {
					slog.Debug("skipping resource type", "type", resourceType, "error", err)
					return nil
				}
				// Non-skippable error: log and skip (best-effort)
				slog.Warn("error listing resources", "type", resourceType, "error", err)
				return nil
			}

			mu.Lock()
			results[resourceType] = resources
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}

// listResourcesByType enumerates all resources of a specific type with pagination
func (e *ResourceEnumerator) listResourcesByType(ctx context.Context, resourceType string) ([]output.CloudResource, error) {
	var allResources []output.CloudResource
	var nextToken *string

	for {
		// Check context cancellation in pagination loop
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

		result, err := e.Client.ListResources(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list resources of type %s: %w", resourceType, err)
		}

		// Convert resource descriptions to CloudResource
		for _, desc := range result.ResourceDescriptions {
			cr := descriptionToCloudResource(desc, resourceType, e.AccountID, e.Region)
			allResources = append(allResources, cr)
		}

		nextToken = result.NextToken
		if nextToken == nil {
			break
		}
	}

	return allResources, nil
}

// descriptionToCloudResource converts a CloudControl ResourceDescription to output.CloudResource
func descriptionToCloudResource(desc cctypes.ResourceDescription, resourceType, accountID, region string) output.CloudResource {
	// Determine region (global services get empty region)
	var erdRegion string
	if helpers.IsGlobalService(resourceType) {
		erdRegion = ""
	} else {
		erdRegion = region
	}

	// Create EnrichedResourceDescription
	erd := types.NewEnrichedResourceDescription(
		*desc.Identifier,
		resourceType,
		erdRegion,
		accountID,
		*desc.Properties,
	)

	return erd.ToCloudResource()
}

// isSkippableCloudControlError checks if an error should be skipped (not fatal)
func isSkippableCloudControlError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return strings.Contains(errStr, "TypeNotFoundException") ||
		strings.Contains(errStr, "UnsupportedActionException") ||
		strings.Contains(errStr, "AccessDeniedException")
}

// keySummaryResourceTypes returns a subset of important AWS resource types
func keySummaryResourceTypes() []string {
	return []string{
		"AWS::EC2::Instance",
		"AWS::S3::Bucket",
		"AWS::Lambda::Function",
		"AWS::DynamoDB::Table",
		"AWS::RDS::DBInstance",
		"AWS::IAM::Role",
		"AWS::IAM::User",
		"AWS::ECS::Cluster",
		"AWS::EKS::Cluster",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
	}
}

// allResourceTypes returns a comprehensive list of CloudControl-supported resource types
func allResourceTypes() []string {
	return []string{
		"AWS::EC2::Instance",
		"AWS::EC2::VPC",
		"AWS::EC2::Subnet",
		"AWS::EC2::SecurityGroup",
		"AWS::EC2::Volume",
		"AWS::S3::Bucket",
		"AWS::Lambda::Function",
		"AWS::DynamoDB::Table",
		"AWS::RDS::DBInstance",
		"AWS::RDS::DBCluster",
		"AWS::IAM::Role",
		"AWS::IAM::User",
		"AWS::IAM::Policy",
		"AWS::ECS::Cluster",
		"AWS::ECS::Service",
		"AWS::EKS::Cluster",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::CloudFormation::Stack",
		"AWS::KMS::Key",
		"AWS::SecretsManager::Secret",
		"AWS::CloudWatch::Alarm",
		"AWS::ApiGateway::RestApi",
		"AWS::ApiGatewayV2::Api",
		"AWS::ElasticLoadBalancingV2::LoadBalancer",
		"AWS::AutoScaling::AutoScalingGroup",
	}
}
