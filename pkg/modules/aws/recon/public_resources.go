package recon

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/aws/publicaccess"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcepolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSPublicResourcesModule{})
}

// PublicResourcesConfig holds the typed parameters for public-resources module.
type PublicResourcesConfig struct {
	plugin.AWSCommonRecon
	OrgPoliciesFile string `param:"org-policies" desc:"Path to org policies JSON file"`
}

// AWSPublicResourcesModule finds publicly accessible AWS resources through
// policy evaluation, property inspection, and enrichment.
type AWSPublicResourcesModule struct {
	PublicResourcesConfig
}

// propertyBasedTypes are checked via resource properties (set by enrichers)
var propertyBasedTypes = map[string]bool{
	"AWS::EC2::Instance":     true,
	"AWS::Cognito::UserPool": true,
	"AWS::RDS::DBInstance":   true,
}

// policyBasedTypes are checked via resource policy evaluation
var policyBasedTypes = map[string]bool{
	"AWS::S3::Bucket":                true,
	"AWS::SNS::Topic":                true,
	"AWS::SQS::Queue":                true,
	"AWS::Lambda::Function":          true,
	"AWS::EFS::FileSystem":           true,
	// Note: OpenSearch and Elasticsearch domains do not support CloudControl LIST.
	// They require a custom lister via the OpenSearch/Elasticsearch SDK.
}

func (m *AWSPublicResourcesModule) ID() string                { return "public-resources" }
func (m *AWSPublicResourcesModule) Name() string              { return "AWS Public Resources" }
func (m *AWSPublicResourcesModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSPublicResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSPublicResourcesModule) OpsecLevel() string        { return "moderate" }
func (m *AWSPublicResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSPublicResourcesModule) Description() string {
	return "Finds publicly accessible AWS resources through policy evaluation, property inspection, and enrichment. " +
		"Combines resource listing, enrichment, policy fetching, and public access evaluation to identify " +
		"resources that are exposed to the internet or allow anonymous access."
}

func (m *AWSPublicResourcesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html",
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSPublicResourcesModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::EC2::Instance",
		"AWS::S3::Bucket",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::Lambda::Function",
		"AWS::EFS::FileSystem",
		"AWS::Cognito::UserPool",
		"AWS::RDS::DBInstance",

	}
}

func (m *AWSPublicResourcesModule) Parameters() any {
	return &m.PublicResourcesConfig
}

func (m *AWSPublicResourcesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.PublicResourcesConfig

	// Resolve regions
	resolvedRegions, err := resolveRegions(c.Regions, c.Profile, c.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve regions: %w", err)
	}

	// Load org policies if specified
	var orgPolicies *orgpolicies.OrgPolicies
	if c.OrgPoliciesFile != "" {
		orgPolicies, err = iam.LoadJSONFile[orgpolicies.OrgPolicies](c.OrgPoliciesFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load org policies file: %w", err)
		}
	}

	// Create CloudControl lister to enumerate resources
	lister := cclist.NewCloudControlLister(c.AWSCommonRecon)

	// List all supported resource types across resolved regions
	allResources, err := lister.List(resolvedRegions, m.SupportedResourceTypes())
	if err != nil {
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}

	// Flatten the map[string][]CloudResource
	var resourcesList []output.CloudResource
	for _, resources := range allResources {
		resourcesList = append(resourcesList, resources...)
	}

	// For each region, enrich and evaluate public access
	var publicResources []output.CloudResource
	for _, region := range resolvedRegions {
		// Filter resources for this region
		var regionResources []output.CloudResource
		for _, resource := range resourcesList {
			if resource.Region == region {
				regionResources = append(regionResources, resource)
			}
		}

		if len(regionResources) == 0 {
			continue
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

		// Get account ID for this region
		accountID, err := awshelpers.GetAccountId(awsCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to get account ID for %s: %w", region, err)
		}

		// Create enricher config
		enricherCfg := plugin.EnricherConfig{
			Context:   cfg.Context,
			AWSConfig: awsCfg,
		}

		// Enrich each resource
		for i := range regionResources {
			enrichers := plugin.GetEnrichers(regionResources[i].ResourceType)
			for _, enrichFn := range enrichers {
				if err := enrichFn(enricherCfg, &regionResources[i]); err != nil {
					slog.Warn("enricher failed",
						"type", regionResources[i].ResourceType,
						"resource", regionResources[i].ResourceID,
						"error", err,
					)
				}
			}
		}

		// Create S3 extended client for this region
		s3Client := s3.NewFromConfig(awsCfg)

		// Evaluate each resource for public access
		for i := range regionResources {
			resource := &regionResources[i]
			resourceType := resource.ResourceType

			if resource.Properties == nil {
				resource.Properties = make(map[string]any)
			}

			added := false

			// Check property-based types
			if propertyBasedTypes[resourceType] {
				result := checkPropertyBasedAccess(resource)
				if result != nil && (result.IsPublic || result.NeedsManualTriage) {
					setPublicAccessResult(resource, result)
					publicResources = append(publicResources, *resource)
					added = true
				}
			}

			// Check policy-based types
			if policyBasedTypes[resourceType] {
				result := evaluatePolicyBasedAccess(
					cfg, resource, resourceType, awsCfg,
					s3Client, accountID, resolvedRegions, orgPolicies,
				)
				if result != nil && (result.IsPublic || result.NeedsManualTriage) {
					setPublicAccessResult(resource, result)
					if !added {
						publicResources = append(publicResources, *resource)
						added = true
					}
				}
			}

			// Special case: Lambda with FunctionUrl and AuthType NONE
			if resourceType == "AWS::Lambda::Function" && !added {
				if authType, ok := resource.Properties["FunctionUrlAuthType"].(string); ok && authType == "NONE" {
					result := &publicaccess.PublicAccessResult{
						IsPublic:          true,
						AllowedActions:    []string{"lambda:InvokeFunctionUrl"},
						EvaluationReasons: []string{"Lambda function URL has AuthType NONE (unauthenticated access)"},
					}
					setPublicAccessResult(resource, result)
					publicResources = append(publicResources, *resource)
				}
			}
		}
	}

	return []plugin.Result{
		{
			Data: publicResources,
			Metadata: map[string]any{
				"module":   m.ID(),
				"platform": m.Platform(),
				"regions":  resolvedRegions,
				"count":    len(publicResources),
			},
		},
	}, nil
}

// setPublicAccessResult marshals the PublicAccessResult and stores it on the resource.
func setPublicAccessResult(resource *output.CloudResource, result *publicaccess.PublicAccessResult) {
	resultJSON, err := json.Marshal(result)
	if err == nil {
		resource.Properties["PublicAccessResult"] = json.RawMessage(resultJSON)
	}
}

// checkPropertyBasedAccess evaluates property-based resource types for public access.
func checkPropertyBasedAccess(resource *output.CloudResource) *publicaccess.PublicAccessResult {
	switch resource.ResourceType {
	case "AWS::EC2::Instance":
		// CloudControl uses "PublicIp", CloudFormation uses "PublicIpAddress"
		publicIP, _ := resource.Properties["PublicIp"].(string)
		if publicIP == "" {
			publicIP, _ = resource.Properties["PublicIpAddress"].(string)
		}
		if publicIP != "" {
			return &publicaccess.PublicAccessResult{
				IsPublic:          true,
				NeedsManualTriage: true,
				AllowedActions:    []string{"ec2:NetworkAccess"},
				EvaluationReasons: []string{
					fmt.Sprintf("EC2 instance has public IP %s; security groups and NACLs require manual review", publicIP),
				},
			}
		}

	case "AWS::RDS::DBInstance":
		isPublic, _ := resource.Properties["IsPubliclyAccessible"].(bool)
		if isPublic {
			return &publicaccess.PublicAccessResult{
				IsPublic: true,
				EvaluationReasons: []string{
					"RDS instance is publicly accessible (PubliclyAccessible=true)",
				},
			}
		}

	case "AWS::Cognito::UserPool":
		selfSignup, _ := resource.Properties["SelfSignupEnabled"].(bool)
		if selfSignup {
			return &publicaccess.PublicAccessResult{
				IsPublic: true,
				EvaluationReasons: []string{
					"Cognito user pool allows self-signup (AdminCreateUserOnly=false)",
				},
			}
		}
	}

	return nil
}

// evaluatePolicyBasedAccess fetches the resource policy and evaluates it for public access.
func evaluatePolicyBasedAccess(
	cfg plugin.Config,
	resource *output.CloudResource,
	resourceType string,
	awsCfg aws.Config,
	s3Client *s3.Client,
	accountID string,
	resolvedRegions []string,
	orgPols *orgpolicies.OrgPolicies,
) *publicaccess.PublicAccessResult {
	var policy *types.Policy
	var err error

	switch resourceType {
	case "AWS::S3::Bucket":
		policy, err = resourcepolicies.FetchS3BucketPolicyExtended(cfg.Context, s3Client, resource, resolvedRegions)
	default:
		fetcher, ok := resourcepolicies.Fetchers[resourceType]
		if !ok {
			return nil
		}
		policy, err = fetcher(cfg.Context, awsCfg, resource)
	}

	if err != nil {
		slog.Warn("failed to fetch policy",
			"type", resourceType,
			"resource", resource.ResourceID,
			"error", err,
		)
		return nil
	}

	if policy == nil {
		return nil
	}

	resourceARN := resource.ARN
	if resourceARN == "" {
		resourceARN = resource.ResourceID
	}

	result, err := publicaccess.EvaluateResourcePolicy(policy, resourceARN, accountID, resourceType, orgPols)
	if err != nil {
		slog.Warn("failed to evaluate resource policy",
			"type", resourceType,
			"resource", resource.ResourceID,
			"error", err,
		)
		return nil
	}

	return result
}

