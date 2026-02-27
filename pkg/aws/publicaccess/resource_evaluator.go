package publicaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcepolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// propertyBasedTypes are checked via resource properties (set by enrichers).
var propertyBasedTypes = map[string]bool{
	"AWS::EC2::Instance":     true,
	"AWS::Cognito::UserPool": true,
	"AWS::RDS::DBInstance":   true,
}

// policyBasedTypes are checked via resource policy evaluation.
var policyBasedTypes = map[string]bool{
	"AWS::S3::Bucket":       true,
	"AWS::SNS::Topic":       true,
	"AWS::SQS::Queue":       true,
	"AWS::Lambda::Function": true,
	"AWS::EFS::FileSystem":  true,
}

// supportedTypes is the combined list of all evaluated resource types.
var supportedTypes = []string{
	"AWS::EC2::Instance",
	"AWS::S3::Bucket",
	"AWS::SNS::Topic",
	"AWS::SQS::Queue",
	"AWS::Lambda::Function",
	"AWS::EFS::FileSystem",
	"AWS::Cognito::UserPool",
	"AWS::RDS::DBInstance",
}

// SupportedResourceTypes returns all resource types the evaluator handles.
func SupportedResourceTypes() []string {
	return supportedTypes
}

// ResourceEvaluator evaluates AWS resources for public access using property
// inspection and policy evaluation. It follows the same pattern as
// resourcepolicies.ResourcePolicyCollector.
type ResourceEvaluator struct {
	opts             plugin.AWSCommonRecon
	crossRegionActor *ratelimit.CrossRegionActor
	regions          []string
	orgPolicies      *orgpolicies.OrgPolicies
}

// NewResourceEvaluator creates a new ResourceEvaluator.
func NewResourceEvaluator(opts plugin.AWSCommonRecon, regions []string, orgPolicies *orgpolicies.OrgPolicies) *ResourceEvaluator {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	return &ResourceEvaluator{
		opts:             opts,
		crossRegionActor: ratelimit.NewCrossRegionActor(concurrency),
		regions:          regions,
		orgPolicies:      orgPolicies,
	}
}

// SupportedResourceTypes returns all resource types this evaluator handles.
func (e *ResourceEvaluator) SupportedResourceTypes() []string {
	return supportedTypes
}

// Evaluate is a pipeline-compatible method that evaluates a single resource for
// public access and sends it downstream if public or needing triage.
func (e *ResourceEvaluator) Evaluate(resource output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	return e.crossRegionActor.ActInRegion(resource.Region, func() error {
		if resource.Properties == nil {
			resource.Properties = make(map[string]any)
		}

		awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     resource.Region,
			Profile:    e.opts.Profile,
			ProfileDir: e.opts.ProfileDir,
		})
		if err != nil {
			slog.Warn("failed to create AWS config, skipping resource",
				"resource", resource.ResourceID, "region", resource.Region, "error", err)
			return nil
		}

		accountID, err := awshelpers.GetAccountId(awsCfg)
		if err != nil {
			slog.Warn("failed to get account ID, skipping resource",
				"resource", resource.ResourceID, "region", resource.Region, "error", err)
			return nil
		}

		result := e.evaluate(&resource, awsCfg, accountID)
		if result != nil && (result.IsPublic || result.NeedsManualTriage) {
			setResult(&resource, result)
			out.Send(resource)
		}

		return nil
	})
}

// evaluate consolidates property-based, policy-based, and Lambda FunctionUrl
// checks into a single evaluation that returns the first positive result.
func (e *ResourceEvaluator) evaluate(resource *output.AWSResource, awsCfg aws.Config, accountID string) *PublicAccessResult {
	resourceType := resource.ResourceType

	if propertyBasedTypes[resourceType] {
		if result := checkPropertyAccess(resource); result != nil {
			return result
		}
	}

	if policyBasedTypes[resourceType] {
		result := e.evaluatePolicyAccess(resource, resourceType, awsCfg, accountID)
		if result != nil && (result.IsPublic || result.NeedsManualTriage) {
			return result
		}
	}

	// Special case: Lambda with FunctionUrl and AuthType NONE
	if resourceType == "AWS::Lambda::Function" {
		if authType, ok := resource.Properties["FunctionUrlAuthType"].(string); ok && authType == "NONE" {
			return &PublicAccessResult{
				IsPublic:          true,
				AllowedActions:    []string{"lambda:InvokeFunctionUrl"},
				EvaluationReasons: []string{"Lambda function URL has AuthType NONE (unauthenticated access)"},
			}
		}
	}

	return nil
}

// checkPropertyAccess evaluates property-based resource types for public access.
func checkPropertyAccess(resource *output.AWSResource) *PublicAccessResult {
	switch resource.ResourceType {
	case "AWS::EC2::Instance":
		publicIP, _ := resource.Properties["PublicIp"].(string)
		if publicIP == "" {
			publicIP, _ = resource.Properties["PublicIpAddress"].(string)
		}
		if publicIP != "" {
			return &PublicAccessResult{
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
			return &PublicAccessResult{
				IsPublic: true,
				EvaluationReasons: []string{
					"RDS instance is publicly accessible (PubliclyAccessible=true)",
				},
			}
		}

	case "AWS::Cognito::UserPool":
		selfSignup, _ := resource.Properties["SelfSignupEnabled"].(bool)
		if selfSignup {
			return &PublicAccessResult{
				IsPublic: true,
				EvaluationReasons: []string{
					"Cognito user pool allows self-signup (AdminCreateUserOnly=false)",
				},
			}
		}
	}

	return nil
}

// evaluatePolicyAccess fetches the resource policy and evaluates it for public access.
func (e *ResourceEvaluator) evaluatePolicyAccess(
	resource *output.AWSResource,
	resourceType string,
	awsCfg aws.Config,
	accountID string,
) *PublicAccessResult {
	ctx := context.Background()

	var policy *types.Policy
	var err error

	switch resourceType {
	case "AWS::S3::Bucket":
		client := s3.NewFromConfig(awsCfg)
		policy, err = resourcepolicies.FetchS3BucketPolicyExtended(ctx, client, resource, e.regions)
	case "AWS::Lambda::Function":
		client := lambda.NewFromConfig(awsCfg)
		policy, err = resourcepolicies.FetchLambdaPolicy(ctx, client, resource)
	case "AWS::SNS::Topic":
		client := sns.NewFromConfig(awsCfg)
		policy, err = resourcepolicies.FetchSNSTopicPolicy(ctx, client, resource)
	case "AWS::SQS::Queue":
		client := sqs.NewFromConfig(awsCfg)
		policy, err = resourcepolicies.FetchSQSQueuePolicy(ctx, client, resource)
	case "AWS::EFS::FileSystem":
		client := efs.NewFromConfig(awsCfg)
		policy, err = resourcepolicies.FetchEFSPolicy(ctx, client, resource)
	default:
		return nil
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

	result, err := EvaluateResourcePolicy(policy, resourceARN, accountID, resourceType, e.orgPolicies)
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

// setResult marshals the PublicAccessResult and stores it on the resource.
func setResult(resource *output.AWSResource, result *PublicAccessResult) {
	resultJSON, err := json.Marshal(result)
	if err == nil {
		resource.Properties["PublicAccessResult"] = json.RawMessage(resultJSON)
	}
}
