package recon

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
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

func (m *AWSListAllResourcesModule) ID() string                { return "list-all" }
func (m *AWSListAllResourcesModule) Name() string              { return "AWS List All Resources" }
func (m *AWSListAllResourcesModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSListAllResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSListAllResourcesModule) OpsecLevel() string        { return "moderate" }
func (m *AWSListAllResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSListAllResourcesModule) Description() string {
	return "List resources in an AWS account using CloudControl API. Supports 'full' scan for all resources or 'summary' scan for key services. Can scan multiple regions concurrently."
}

func (m *AWSListAllResourcesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/Welcome.html",
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSListAllResourcesModule) SupportedResourceTypes() []string {
	return resourcetypes.GetAll()
}

func (m *AWSListAllResourcesModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("scan-type", "Scan type - 'full' for all resources or 'summary' for key services",
			plugin.WithDefault("full"),
			plugin.WithShortcode("s"),
			plugin.WithEnum("full", "summary"),
		),
		options.AwsRegions(),
		options.AwsProfile(),
		options.AwsProfileDir(),
		plugin.NewParam[int]("concurrency", "Maximum concurrent CloudControl API requests",
			plugin.WithDefault(5),
		),
	}
}

// resolveRegions resolves the "all" keyword to actual enabled regions
func (m *AWSListAllResourcesModule) resolveRegions(
	regions []string, profile string, opts []*types.Option,
) ([]string, error) {
	if len(regions) == 1 && strings.ToLower(regions[0]) == "all" {
		return helpers.EnabledRegions(profile, opts)
	}
	return regions, nil
}

// selectResourceTypes returns resource types based on scan type
func (m *AWSListAllResourcesModule) selectResourceTypes(scanType string) []string {
	if strings.ToLower(scanType) == "summary" {
		return resourcetypes.GetSummary()
	}
	return resourcetypes.GetAll()
}

// processRegion enumerates resources in a single AWS region
func (m *AWSListAllResourcesModule) processRegion(
	ctx context.Context,
	region string,
	profile string,
	opts []*types.Option,
	resourceTypes []string,
	concurrency int,
) (map[string][]output.CloudResource, error) {
	// Create region-specific AWS config
	awsCfg, err := helpers.GetAWSCfg(region, profile, opts, "moderate")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config for region %s: %w", region, err)
	}

	// Get account ID (best effort)
	accountID, _ := helpers.GetAccountId(awsCfg)

	// Create region-specific CloudControl client
	client := cloudcontrol.NewFromConfig(awsCfg)

	// List all resources in this region
	return cclist.ListAll(ctx, client, cclist.ListOptions{
		ResourceTypes: resourceTypes,
		AccountID:     accountID,
		Region:        region,
		Concurrency:   concurrency,
	})
}

// flattenResults flattens nested region/resourceType results into a single map
func (m *AWSListAllResourcesModule) flattenResults(
	allResults map[string]map[string][]output.CloudResource,
) map[string][]output.CloudResource {
	flatResults := make(map[string][]output.CloudResource)
	for region, regionResults := range allResults {
		for rt, resources := range regionResults {
			key := fmt.Sprintf("%s/%s", region, rt)
			flatResults[key] = resources
		}
	}
	return flatResults
}

func (m *AWSListAllResourcesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	params := plugin.NewParameters(m.Parameters()...)

	for k, v := range cfg.Args {
		params.Set(k, v)
	}

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("parameter validation failed: %w", err)
	}

	scanType := params.String("scan-type")
	regions := params.StringSlice("regions")
	profile := params.String("profile")
	profileDir := params.String("profile-dir")
	concurrency := params.Int("concurrency")

	var opts []*types.Option
	if profileDir != "" {
		opts = append(opts, &types.Option{
			Name:  "profile-dir",
			Value: profileDir,
		})
	}

	// Resolve regions (handles "all" keyword)
	resolvedRegions, err := m.resolveRegions(regions, profile, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve regions: %w", err)
	}

	// Select resource types based on scan type
	resourceTypes := m.selectResourceTypes(scanType)

	// Create rate limiter for multi-region concurrency
	limiter := ratelimit.NewAWSRegionLimiter(concurrency)

	// Aggregated results from all regions
	allResults := make(map[string]map[string][]output.CloudResource)
	var mu sync.Mutex

	// Use errgroup for concurrent region processing
	g, ctx := errgroup.WithContext(cfg.Context)
	g.SetLimit(concurrency)

	for _, region := range resolvedRegions {
		region := region // capture loop variable

		g.Go(func() error {
			// Acquire rate limit for this region
			release, err := limiter.Acquire(ctx, region)
			if err != nil {
				return nil // Context cancelled
			}
			defer release()

			// Process this region
			results, err := m.processRegion(ctx, region, profile, opts, resourceTypes, concurrency)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("failed to enumerate resources in region %s: %w", region, err)
			}

			// Merge results into aggregated map
			mu.Lock()
			if allResults[region] == nil {
				allResults[region] = make(map[string][]output.CloudResource)
			}
			for rt, resources := range results {
				allResults[region][rt] = resources
			}
			mu.Unlock()

			return nil
		})
	}

	// Wait for all region goroutines to complete
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Flatten results for output
	flatResults := m.flattenResults(allResults)

	return []plugin.Result{
		{
			Data: flatResults,
			Metadata: map[string]any{
				"module":      "list-all",
				"platform":    "aws",
				"opsec_level": "moderate",
				"regions":     resolvedRegions,
			},
		},
	}, nil
}
