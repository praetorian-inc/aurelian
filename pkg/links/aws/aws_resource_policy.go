package aws

import (
	"context"
	"encoding/json"
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
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	iam "github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsResourcePolicyChecker struct {
	*AwsReconLink
}

func NewAwsResourcePolicyChecker(configs ...cfg.Config) chain.Link {
	r := &AwsResourcePolicyChecker{}
	r.AwsReconLink = NewAwsReconLink(r, configs...)
	return r
}

func (u *AwsResourcePolicyChecker) Process(resource *types.EnrichedResourceDescription) error {
	// Check if we have a configuration for this resource type
	serviceConfig, ok := ServiceMap[resource.TypeName]
	if !ok {
		// Skip this resource type
		return nil
	}

	// Parse resource properties
	var props map[string]interface{}
	switch p := resource.Properties.(type) {
	case string:
		err := json.Unmarshal([]byte(p), &props)
		if err != nil {
			return fmt.Errorf("failed to unmarshal resource properties: %w", err)
		}
	case map[string]interface{}:
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
	awsCfg, err := helpers.GetAWSCfg(resource.Region, u.profile, options.JanusParamAdapter(u.Params()))
	if err != nil {
		slog.Error("Failed to get AWS config", "region", resource.Region, "error", err)
		return nil // Continue with other resources
	}

	// Get the policy
	policy, err := ServiceMap[resource.TypeName].GetPolicy(context.TODO(), awsCfg, identifierStr)
	if err != nil {
		slog.Debug("Failed to get policy", "resource", identifierStr, "type", resource.TypeName, "error", err)
		return nil // Continue with other resources
	}

	// Skip if no policy
	if policy == "" {
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
	u.Send(enriched)
	return nil
}

// analyzePolicy analyzes a policy to determine if it grants public access
func analyzePolicy(resource, policyStr string) ([]*iam.EvaluationResult, error) {
	results := []*iam.EvaluationResult{}
	var policy types.Policy
	err := json.Unmarshal([]byte(policyStr), &policy)
	if err != nil {
		return results, err
	}

	pd := &iam.PolicyData{
		ResourcePolicies: map[string]*types.Policy{
			resource: &policy,
		},
	}

	evaluator := iam.NewPolicyEvaluator(pd)

	reqCtx := &iam.RequestContext{
		// represents an arbitrary principal that is not the resource owner
		PrincipalArn: "arn:aws:iam::111122223333:role/praetorian",
	}
	reqCtx.PopulateDefaultRequestConditionKeys(resource)

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

type ServicePolicyConfig struct {
	// GetPolicy retrieves the policy for the given identifier
	GetPolicy func(ctx context.Context, cfg aws.Config, identifier string) (string, error)

	// IdentifierField is the name of the field in ResourceDescription.Properties to use as identifier
	IdentifierField string

	// PolicyField is the name of the field to store the policy in the output
	PolicyField string
}

// ServiceMap maps AWS resource types to their policy checking configurations
var ServiceMap = map[string]ServicePolicyConfig{
	"AWS::S3::Bucket": {
		GetPolicy: func(ctx context.Context, cfg aws.Config, bucketName string) (string, error) {
			client := s3.NewFromConfig(cfg)
			resp, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				// Handle "no policy" errors gracefully
				if strings.Contains(err.Error(), "NoSuchBucketPolicy") {
					return "", nil
				}
				return "", err
			}
			if resp.Policy == nil {
				return "", nil
			}
			return *resp.Policy, nil
		},
		IdentifierField: "BucketName",
		PolicyField:     "AccessPolicy",
	},
	"AWS::SNS::Topic": {
		GetPolicy: func(ctx context.Context, cfg aws.Config, topicArn string) (string, error) {
			client := sns.NewFromConfig(cfg)
			resp, err := client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
				TopicArn: aws.String(topicArn),
			})
			if err != nil {
				// Handle "no policy" errors gracefully
				if strings.Contains(err.Error(), "NoSuchEntityException") {
					return "", nil
				}
				return "", err
			}
			policy, ok := resp.Attributes["Policy"]
			if !ok {
				return "", nil
			}
			return policy, nil
		},
		IdentifierField: "TopicArn",
		PolicyField:     "AccessPolicy",
	},
	"AWS::SQS::Queue": {
		GetPolicy: func(ctx context.Context, cfg aws.Config, queueUrl string) (string, error) {
			client := sqs.NewFromConfig(cfg)
			resp, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl:       aws.String(queueUrl),
				AttributeNames: []sqstypes.QueueAttributeName{"Policy"},
			})
			if err != nil {
				// Handle "no policy" errors gracefully
				if strings.Contains(err.Error(), "NoSuchEntityException") {
					return "", nil
				}
				return "", err
			}
			policy, ok := resp.Attributes["Policy"]
			if !ok {
				return "", nil
			}
			return policy, nil
		},
		IdentifierField: "QueueUrl",
		PolicyField:     "AccessPolicy",
	},
	"AWS::Lambda::Function": {
		GetPolicy: func(ctx context.Context, cfg aws.Config, functionName string) (string, error) {
			client := lambda.NewFromConfig(cfg)
			resp, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{
				FunctionName: aws.String(functionName),
			})
			if err != nil {
				// Handle "no policy" errors gracefully
				if strings.Contains(err.Error(), "ResourceNotFoundException") {
					return "", nil
				}
				return "", err
			}
			if resp.Policy == nil {
				return "", nil
			}
			return *resp.Policy, nil
		},
		IdentifierField: "FunctionName",
		PolicyField:     "AccessPolicy",
	},
	"AWS::EFS::FileSystem": {
		GetPolicy: func(ctx context.Context, cfg aws.Config, fileSystemId string) (string, error) {
			client := efs.NewFromConfig(cfg)
			resp, err := client.DescribeFileSystemPolicy(ctx, &efs.DescribeFileSystemPolicyInput{
				FileSystemId: aws.String(fileSystemId),
			})
			if err != nil {
				// Handle "no policy" errors gracefully
				if strings.Contains(err.Error(), "PolicyNotFound") ||
					strings.Contains(err.Error(), "FileSystemNotFound") {
					return "", nil
				}
				return "", err
			}
			if resp.Policy == nil {
				return "", nil
			}
			return *resp.Policy, nil
		},
		IdentifierField: "FileSystemId",
		PolicyField:     "AccessPolicy",
	},
	"AWS::ElasticSearch::Domain": {
		GetPolicy: func(ctx context.Context, cfg aws.Config, domainName string) (string, error) {
			client := elasticsearchservice.NewFromConfig(cfg)
			resp, err := client.DescribeElasticsearchDomainConfig(ctx, &elasticsearchservice.DescribeElasticsearchDomainConfigInput{
				DomainName: aws.String(domainName),
			})
			if err != nil {
				// Handle "no policy" errors gracefully
				if strings.Contains(err.Error(), "ResourceNotFoundException") {
					return "", nil
				}
				return "", err
			}
			if resp.DomainConfig.AccessPolicies == nil || resp.DomainConfig.AccessPolicies.Options == nil {
				return "", nil
			}
			return *resp.DomainConfig.AccessPolicies.Options, nil
		},
		IdentifierField: "DomainName",
		PolicyField:     "AccessPolicy",
	},
}
