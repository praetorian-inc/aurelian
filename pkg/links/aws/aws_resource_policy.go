package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	iam "github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsResourcePolicyChecker struct {
	*base.AwsReconLink
}

func NewAwsResourcePolicyChecker(configs ...cfg.Config) chain.Link {
	r := &AwsResourcePolicyChecker{}
	r.AwsReconLink = base.NewAwsReconLink(r, configs...)
	return r
}

func (a *AwsResourcePolicyChecker) Process(resource *types.EnrichedResourceDescription) error {
	// Check if we have a configuration for this resource type
	serviceConfig, ok := ServiceMap[resource.TypeName]
	if !ok {
		// Skip this resource type
		return nil
	}

	// Parse resource properties
	var props map[string]any
	switch p := resource.Properties.(type) {
	case string:
		err := json.Unmarshal([]byte(p), &props)
		if err != nil {
			return fmt.Errorf("failed to unmarshal resource properties: %w", err)
		}
	case map[string]any:
		props = p
	default:
		return fmt.Errorf("unexpected properties type: %T", resource.Properties)
	}

	// Extract the identifier
	identifier, ok := props[serviceConfig.IdentifierField]
	if !ok {
		return fmt.Errorf("resource does not have identifier field '%s'", serviceConfig.IdentifierField)
	}

	identifierStr, ok := identifier.(string)
	if !ok {
		return fmt.Errorf("identifier is not a string: %v", identifier)
	}

	// Get AWS config
	awsCfg, err := a.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Error("Failed to get AWS config", "region", resource.Region, "error", err)
		return nil // Continue with other resources
	}

	// Get the policy
	policy, err := ServiceMap[resource.TypeName].GetPolicy(context.TODO(), awsCfg, identifierStr, a.Regions)
	if err != nil {
		slog.Debug("Failed to get policy", "resource", identifierStr, "type", resource.TypeName, "error", err)
		return nil // Continue with other resources
	}

	// Skip if no policy
	if policy == nil {
		return nil
	}

	// Check if the policy allows public access
	res, err := analyzePolicy(resource.Arn.String(), policy)
	if err != nil {
		slog.Error("Failed to analyze policy", "resource", identifierStr, "error", err)
		return err
	}

	// Skip if not public
	if !isPublic(res) {
		return nil
	}

	// Add the policy to the properties
	props[serviceConfig.PolicyField] = policy
	props["EvaluationReasons"] = getUnqiueDetails(res)
	props["NeedsManualTriage"] = hasInconclusiveConditions(res)
	props["Actions"] = getAllowedActions(res)

	// Create enriched resource with the policy
	enriched := types.EnrichedResourceDescription{
		Identifier: resource.Identifier,
		TypeName:   resource.TypeName,
		Region:     resource.Region,
		Properties: props,
		AccountId:  resource.AccountId,
		Arn:        resource.Arn,
	}

	// Send the enriched resource
	a.Send(enriched)
	return nil
}

// analyzePolicy analyzes a policy to determine if it grants public access
func analyzePolicy(resource string, policy *types.Policy) ([]*iam.EvaluationResult, error) {
	results := []*iam.EvaluationResult{}

	pd := &iam.PolicyData{
		ResourcePolicies: map[string]*types.Policy{
			resource: policy,
		},
	}

	evaluator := iam.NewPolicyEvaluator(pd)

	reqCtx := &iam.RequestContext{
		// represents an arbitrary principal that is not the resource owner
		PrincipalArn: "arn:aws:iam::111122223333:role/praetorian",
	}
	reqCtx.PopulateDefaultRequestConditionKeys(resource)
	if policy.Statement == nil {
		return results, errors.New("policy statement is nil")
	}

	actions := iam.ExtractActions(policy.Statement)
	for _, action := range actions {
		er := &iam.EvaluationRequest{
			Action:             action,
			Resource:           resource,
			Context:            reqCtx,
			IdentityStatements: &types.PolicyStatementList{}, // purposely empty
		}

		res, err := evaluator.Evaluate(er)
		if err != nil {
			return results, err
		}

		slog.Debug("Policy evaluation result", "principal", reqCtx.PrincipalArn, "resource", resource, "action", action, "allowed", res.Allowed, "EvaluationResult", res)
		results = append(results, res)

	}

	return results, nil
}

func getAllowedResults(results []*iam.EvaluationResult) []*iam.EvaluationResult {
	allowed := []*iam.EvaluationResult{}
	for _, res := range results {
		if res.Allowed {
			allowed = append(allowed, res)
		}
	}
	return allowed
}

func isPublic(results []*iam.EvaluationResult) bool {
	allowed := getAllowedResults(results)
	return len(allowed) > 0
}

func getAllowedActions(results []*iam.EvaluationResult) []string {
	allowed := getAllowedResults(results)
	actions := []string{}
	for _, res := range allowed {
		actions = append(actions, string(res.Action))
	}
	return actions
}

func getUnqiueDetails(results []*iam.EvaluationResult) []string {
	details := []string{}
	for _, res := range results {
		if !slices.Contains(details, res.EvaluationDetails) {
			details = append(details, res.EvaluationDetails)
		}
	}
	return details
}

func hasInconclusiveConditions(results []*iam.EvaluationResult) bool {
	for _, res := range results {
		if res.HasInconclusiveCondition() {
			return true
		}
	}
	return false
}

func strToPolicy(s string) (*types.Policy, error) {
	var p types.Policy
	err := json.Unmarshal([]byte(s), &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

type PolicyGetter func(ctx context.Context, cfg aws.Config, identifier string, allowedRegions []string) (*types.Policy, error)

type ServicePolicyConfig struct {
	// GetPolicy retrieves the policy for the given identifier
	GetPolicy PolicyGetter

	// IdentifierField is the name of the field in ResourceDescription.Properties to use as identifier
	IdentifierField string

	// PolicyField is the name of the field to store the policy in the output
	PolicyField string
}

// ServiceMap maps AWS resource types to their policy checking configurations
var ServiceMap = map[string]ServicePolicyConfig{
	"AWS::S3::Bucket": {
		GetPolicy:       ServicePolicyFuncMap["AWS::S3::Bucket"],
		IdentifierField: "BucketName",
		PolicyField:     "AccessPolicy",
	},
	"AWS::SNS::Topic": {
		GetPolicy:       ServicePolicyFuncMap["AWS::SNS::Topic"],
		IdentifierField: "TopicArn",
		PolicyField:     "AccessPolicy",
	},
	"AWS::SQS::Queue": {
		GetPolicy:       ServicePolicyFuncMap["AWS::SQS::Queue"],
		IdentifierField: "QueueUrl",
		PolicyField:     "AccessPolicy",
	},
	"AWS::Lambda::Function": {
		GetPolicy:       ServicePolicyFuncMap["AWS::Lambda::Function"],
		IdentifierField: "FunctionName",
		PolicyField:     "AccessPolicy",
	},
	"AWS::EFS::FileSystem": {
		GetPolicy:       ServicePolicyFuncMap["AWS::EFS::FileSystem"],
		IdentifierField: "FileSystemId",
		PolicyField:     "AccessPolicy",
	},
	"AWS::ElasticSearch::Domain": {
		GetPolicy:       ServicePolicyFuncMap["AWS::ElasticSearch::Domain"],
		IdentifierField: "DomainName",
		PolicyField:     "AccessPolicy",
	},
}

var ServicePolicyFuncMap = map[string]PolicyGetter{
	"AWS::Lambda::Function": func(ctx context.Context, cfg aws.Config, functionName string, allowedRegions []string) (*types.Policy, error) {
		client := lambda.NewFromConfig(cfg)
		resp, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{
			FunctionName: aws.String(functionName),
		})
		if err != nil {
			// Handle "no policy" errors gracefully
			if strings.Contains(err.Error(), "ResourceNotFoundException") || strings.Contains(err.Error(), "failed to get policy") {
				return nil, nil
			}
			return nil, err
		}
		if resp.Policy == nil {
			return nil, errors.New("no policy found")
		}

		policy, err := strToPolicy(*resp.Policy)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
	"AWS::S3::Bucket": func(ctx context.Context, cfg aws.Config, bucketName string, allowedRegions []string) (*types.Policy, error) {
		client := s3.NewFromConfig(cfg)

		// First, try to get the bucket's location to determine its region
		locationResp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			// If we can't get the location, fall back to the original approach
			slog.Debug("Failed to get bucket location, using original config", "bucket", bucketName, "error", err)
		} else {
			// Create a new config for the bucket's specific region
			bucketRegion := string(locationResp.LocationConstraint)
			// AWS returns empty string for us-east-1
			if bucketRegion == "" {
				bucketRegion = "us-east-1"
			}

			// Check if the bucket's region is in the user's allowed regions list
			if !slices.Contains(allowedRegions, bucketRegion) {
				slog.Debug("Bucket region not in allowed regions list", "bucket", bucketName, "bucketRegion", bucketRegion, "allowedRegions", allowedRegions)
				return nil, nil // Skip this bucket
			}

			// Only create a new client if the bucket is in a different region
			if bucketRegion != cfg.Region {
				newCfg := cfg.Copy()
				newCfg.Region = bucketRegion
				client = s3.NewFromConfig(newCfg)
				slog.Debug("Created region-specific S3 client", "bucket", bucketName, "region", bucketRegion)
			}
		}

		// Check bucket policy
		var bucketPolicy *types.Policy
		resp, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			if !strings.Contains(err.Error(), "NoSuchBucketPolicy") {
				return nil, err
			}
			// NoSuchBucketPolicy is fine, just means no bucket policy exists
		} else if resp.Policy != nil {
			bucketPolicy, err = strToPolicy(*resp.Policy)
			if err != nil {
				return nil, err
			}
		}

		// Return the bucket policy
		return bucketPolicy, nil
	},
	"AWS::EFS::FileSystem": func(ctx context.Context, cfg aws.Config, fileSystemId string, allowedRegions []string) (*types.Policy, error) {
		client := efs.NewFromConfig(cfg)
		resp, err := client.DescribeFileSystemPolicy(ctx, &efs.DescribeFileSystemPolicyInput{
			FileSystemId: aws.String(fileSystemId),
		})
		if err != nil {
			// Handle "no policy" errors gracefully
			if strings.Contains(err.Error(), "PolicyNotFound") ||
				strings.Contains(err.Error(), "FileSystemNotFound") {
				return nil, err
			}
			return nil, err
		}
		if resp.Policy == nil {
			return nil, nil
		}
		policy, err := strToPolicy(*resp.Policy)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
	"AWS::SQS::Queue": func(ctx context.Context, cfg aws.Config, queueUrl string, allowedRegions []string) (*types.Policy, error) {
		client := sqs.NewFromConfig(cfg)
		resp, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
			QueueUrl:       aws.String(queueUrl),
			AttributeNames: []sqstypes.QueueAttributeName{"Policy"},
		})
		if err != nil {
			// Handle "no policy" errors gracefully
			if strings.Contains(err.Error(), "NoSuchEntityException") {
				return &types.Policy{}, nil
			}
			return nil, err
		}
		pol, ok := resp.Attributes["Policy"]
		if !ok {
			return nil, errors.New("no policy found")
		}

		policy, err := strToPolicy(pol)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
	"AWS::ElasticSearch::Domain": func(ctx context.Context, cfg aws.Config, domainName string, allowedRegions []string) (*types.Policy, error) {
		client := elasticsearchservice.NewFromConfig(cfg)
		resp, err := client.DescribeElasticsearchDomainConfig(ctx, &elasticsearchservice.DescribeElasticsearchDomainConfigInput{
			DomainName: aws.String(domainName),
		})
		if err != nil {
			// Handle "no policy" errors gracefully
			if strings.Contains(err.Error(), "ResourceNotFoundException") {
				return nil, err
			}
			return nil, err
		}
		if resp.DomainConfig.AccessPolicies == nil || resp.DomainConfig.AccessPolicies.Options == nil {
			return nil, errors.New("no policy found")
		}

		policy, err := strToPolicy(*resp.DomainConfig.AccessPolicies.Options)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
	"AWS::SNS::Topic": func(ctx context.Context, cfg aws.Config, topicArn string, allowedRegions []string) (*types.Policy, error) {
		client := sns.NewFromConfig(cfg)
		resp, err := client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
			TopicArn: aws.String(topicArn),
		})
		if err != nil {
			// Handle "no policy" errors gracefully
			if strings.Contains(err.Error(), "NoSuchEntityException") {
				return &types.Policy{}, nil
			}
			return &types.Policy{}, err
		}
		pol, ok := resp.Attributes["Policy"]
		if !ok {
			return &types.Policy{}, errors.New("no policy found")
		}

		policy, err := strToPolicy(pol)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
}

type AwsResourcePolicyFetcher struct {
	*base.AwsReconLink
}

func NewAwsResourcePolicyFetcher(configs ...cfg.Config) chain.Link {
	r := &AwsResourcePolicyFetcher{}
	r.AwsReconLink = base.NewAwsReconLink(r, configs...)
	return r
}

func (a *AwsResourcePolicyFetcher) Process(resource *types.EnrichedResourceDescription) error {
	// Get the policy getter function for this resource type
	policyGetter, ok := ServicePolicyFuncMap[resource.TypeName]
	if !ok {
		// Silently skip resources that don't have resource policies
		slog.Debug("Skipping resource type without resource policy", "type", resource.TypeName)
		return nil
	}

	// Get AWS config from the link parameters
	awsCfg, err := a.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		return fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Get the policy
	policy, err := policyGetter(a.ContextHolder.Context(), awsCfg, resource.Identifier, a.Regions)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}

	// Send the policy downstream
	a.Send(policy)
	return nil
}
