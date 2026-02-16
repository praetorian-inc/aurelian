package recon

import (
	"fmt"

	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcepolicies"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSResourcePoliciesModule{})
}

// ResourcePoliciesConfig holds the typed parameters for resource-policies module.
type ResourcePoliciesConfig struct {
	plugin.AWSCommonRecon
}

// AWSResourcePoliciesModule retrieves resource policies for supported AWS services
type AWSResourcePoliciesModule struct {
	config ResourcePoliciesConfig
}

func (m *AWSResourcePoliciesModule) ID() string                { return "resource-policies" }
func (m *AWSResourcePoliciesModule) Name() string              { return "AWS Get Resource Policies" }
func (m *AWSResourcePoliciesModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSResourcePoliciesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSResourcePoliciesModule) OpsecLevel() string        { return "moderate" }
func (m *AWSResourcePoliciesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSResourcePoliciesModule) Description() string {
	return "Retrieves resource-based policies for AWS resources that support them (S3 buckets, Lambda functions, SNS topics, SQS queues, EFS file systems, OpenSearch/Elasticsearch domains). " +
		"Policies are added to the ResourcePolicy property of each resource."
}

func (m *AWSResourcePoliciesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html",
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html",
	}
}

func (m *AWSResourcePoliciesModule) SupportedResourceTypes() []string {
	return resourcepolicies.SupportedResourceTypes()
}

func (m *AWSResourcePoliciesModule) Parameters() any {
	return &m.config
}

func (m *AWSResourcePoliciesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.config

	// Resolve regions
	resolvedRegions, err := resolveRegions(c.Regions, c.Profile, c.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve regions: %w", err)
	}

	// Create CloudControl lister to enumerate resources
	lister := cclist.NewCloudControlLister(c.AWSCommonRecon)

	// List all supported resource types
	allResources, err := lister.List(resolvedRegions, resourcepolicies.SupportedResourceTypes())
	if err != nil {
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}

	// Flatten the map[string][]CloudResource to []CloudResource
	var resourcesList []output.CloudResource
	for _, resources := range allResources {
		resourcesList = append(resourcesList, resources...)
	}

	// For each region, collect policies
	var allResults []output.CloudResource
	for _, region := range resolvedRegions {
		// Filter resources for this region
		var regionResources []output.CloudResource
		for _, resource := range resourcesList {
			if resource.Region == region {
				regionResources = append(regionResources, resource)
			}
		}

		// Get AWS config for this region
		awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     region,
			Profile:    c.Profile,
			ProfileDir: c.ProfileDir,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create AWS config for %s: %w", region, err)
		}

		// Collect policies for resources in this region
		resourcesWithPolicies, err := resourcepolicies.CollectPolicies(cfg.Context, awsCfg, regionResources)
		if err != nil {
			return nil, fmt.Errorf("failed to collect policies in %s: %w", region, err)
		}

		allResults = append(allResults, resourcesWithPolicies...)
	}

	return []plugin.Result{
		{
			Data: allResults,
			Metadata: map[string]any{
				"module":   m.ID(),
				"platform": m.Platform(),
				"regions":  resolvedRegions,
				"count":    len(allResults),
			},
		},
	}, nil
}
