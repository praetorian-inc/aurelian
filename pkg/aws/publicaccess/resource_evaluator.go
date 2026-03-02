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

// evaluator is a function that checks a single resource for public access.
type evaluator func(resource *output.AWSResource, awsCfg aws.Config, accountID string) *PublicAccessResult

// evaluators maps resource types to their evaluation functions.
func (e *ResourceEvaluator) evaluators() map[string]evaluator {
	return map[string]evaluator{
		"AWS::EC2::Instance":     e.evaluateEC2,
		"AWS::RDS::DBInstance":   e.evaluateRDS,
		"AWS::Cognito::UserPool": e.evaluateCognito,
		"AWS::Lambda::Function":  e.evaluateLambda,
		"AWS::S3::Bucket":        e.evaluateS3,
		"AWS::SNS::Topic":        e.evaluateSNS,
		"AWS::SQS::Queue":        e.evaluateSQS,
		"AWS::EFS::FileSystem":   e.evaluateEFS,
	}
}

// SupportedResourceTypes returns all resource types the evaluator handles.
func SupportedResourceTypes() []string {
	// Stable ordering — not derived from map iteration.
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

// ResourceEvaluator evaluates AWS resources for public access using property
// inspection and policy evaluation.
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
	return SupportedResourceTypes()
}

// Evaluate is a pipeline-compatible method that evaluates a single resource for
// public access and sends it downstream if public or needing triage.
func (e *ResourceEvaluator) Evaluate(resource output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	return e.crossRegionActor.ActInRegion(resource.Region, func() error {
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

		e.evaluateCore(&resource, awsCfg, accountID, out)
		return nil
	})
}

// evaluateCore performs the core evaluation logic: looks up the evaluator for
// the resource type, runs it, and sends public/triage results downstream.
func (e *ResourceEvaluator) evaluateCore(resource *output.AWSResource, awsCfg aws.Config, accountID string, out *pipeline.P[output.AWSResource]) {
	if resource.Properties == nil {
		resource.Properties = make(map[string]any)
	}

	eval, ok := e.evaluators()[resource.ResourceType]
	if !ok {
		return
	}

	result := eval(resource, awsCfg, accountID)
	if result != nil && (result.IsPublic || result.NeedsManualTriage) {
		setResult(resource, result)
		out.Send(*resource)
	}
}

// --- property-based evaluators ---

func (e *ResourceEvaluator) evaluateEC2(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	publicIP, _ := resource.Properties["PublicIp"].(string)
	if publicIP == "" {
		publicIP, _ = resource.Properties["PublicIpAddress"].(string)
	}
	if publicIP == "" {
		return nil
	}
	return &PublicAccessResult{
		IsPublic:          true,
		NeedsManualTriage: true,
		AllowedActions:    []string{"ec2:NetworkAccess"},
		EvaluationReasons: []string{
			fmt.Sprintf("EC2 instance has public IP %s; security groups and NACLs require manual review", publicIP),
		},
	}
}

func (e *ResourceEvaluator) evaluateRDS(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	isPublic, _ := resource.Properties["IsPubliclyAccessible"].(bool)
	if !isPublic {
		return nil
	}
	return &PublicAccessResult{
		IsPublic: true,
		EvaluationReasons: []string{
			"RDS instance is publicly accessible (PubliclyAccessible=true)",
		},
	}
}

func (e *ResourceEvaluator) evaluateCognito(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	selfSignup, _ := resource.Properties["SelfSignupEnabled"].(bool)
	if !selfSignup {
		return nil
	}
	return &PublicAccessResult{
		IsPublic: true,
		EvaluationReasons: []string{
			"Cognito user pool allows self-signup (AdminCreateUserOnly=false)",
		},
	}
}

// --- policy-based evaluators ---

func (e *ResourceEvaluator) evaluateS3(resource *output.AWSResource, awsCfg aws.Config, accountID string) *PublicAccessResult {
	client := s3.NewFromConfig(awsCfg)
	policy, err := resourcepolicies.FetchS3BucketPolicyExtended(context.Background(), client, resource, e.regions)
	return e.evaluatePolicy(resource, policy, err, accountID)
}

func (e *ResourceEvaluator) evaluateSNS(resource *output.AWSResource, awsCfg aws.Config, accountID string) *PublicAccessResult {
	client := sns.NewFromConfig(awsCfg)
	policy, err := resourcepolicies.FetchSNSTopicPolicy(context.Background(), client, resource)
	return e.evaluatePolicy(resource, policy, err, accountID)
}

func (e *ResourceEvaluator) evaluateSQS(resource *output.AWSResource, awsCfg aws.Config, accountID string) *PublicAccessResult {
	client := sqs.NewFromConfig(awsCfg)
	policy, err := resourcepolicies.FetchSQSQueuePolicy(context.Background(), client, resource)
	return e.evaluatePolicy(resource, policy, err, accountID)
}

func (e *ResourceEvaluator) evaluateEFS(resource *output.AWSResource, awsCfg aws.Config, accountID string) *PublicAccessResult {
	client := efs.NewFromConfig(awsCfg)
	policy, err := resourcepolicies.FetchEFSPolicy(context.Background(), client, resource)
	return e.evaluatePolicy(resource, policy, err, accountID)
}

func (e *ResourceEvaluator) evaluateLambda(resource *output.AWSResource, awsCfg aws.Config, accountID string) *PublicAccessResult {
	client := lambda.NewFromConfig(awsCfg)
	policy, err := resourcepolicies.FetchLambdaPolicy(context.Background(), client, resource)
	return e.evaluateLambdaAccess(resource, policy, err, accountID)
}

// evaluateLambdaAccess checks both the resource policy and Function URL AuthType
// independently. Function URL endpoints bypass the Lambda resource policy, so a
// permissive policy must not short-circuit the AuthType=NONE check.
func (e *ResourceEvaluator) evaluateLambdaAccess(resource *output.AWSResource, policy *types.Policy, fetchErr error, accountID string) *PublicAccessResult {
	var result *PublicAccessResult

	// Check resource policy.
	if policyResult := e.evaluatePolicy(resource, policy, fetchErr, accountID); policyResult != nil && (policyResult.IsPublic || policyResult.NeedsManualTriage) {
		result = policyResult
	}

	// Check FunctionUrl with AuthType NONE — Function URL endpoints are independent
	// of the Lambda resource policy, so both checks must always run.
	if authType, ok := resource.Properties["FunctionUrlAuthType"].(string); ok && authType == "NONE" {
		urlResult := &PublicAccessResult{
			IsPublic:          true,
			AllowedActions:    []string{"lambda:InvokeFunctionUrl"},
			EvaluationReasons: []string{"Lambda function URL has AuthType NONE (unauthenticated access)"},
		}
		if result == nil {
			result = urlResult
		} else {
			// Merge: both policy and FunctionUrl findings apply.
			result.AllowedActions = append(result.AllowedActions, urlResult.AllowedActions...)
			result.EvaluationReasons = append(result.EvaluationReasons, urlResult.EvaluationReasons...)
		}
	}

	return result
}

// evaluatePolicy is a shared helper that handles the fetch-error / nil-policy /
// evaluate-policy pattern common to all policy-based evaluators.
func (e *ResourceEvaluator) evaluatePolicy(resource *output.AWSResource, policy *types.Policy, fetchErr error, accountID string) *PublicAccessResult {
	if fetchErr != nil {
		slog.Warn("failed to fetch policy",
			"type", resource.ResourceType,
			"resource", resource.ResourceID,
			"error", fetchErr,
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

	result, err := EvaluateResourcePolicy(policy, resourceARN, accountID, resource.ResourceType, e.orgPolicies)
	if err != nil {
		slog.Warn("failed to evaluate resource policy",
			"type", resource.ResourceType,
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
