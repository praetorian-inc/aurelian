package publicaccess

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"sync"

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
		"AWS::Amplify::App":       e.evaluateAmplify,
		"AWS::EC2::Instance":      e.evaluateEC2,
		"AWS::RDS::DBInstance":    e.evaluateRDS,
		"AWS::Redshift::Cluster":  e.evaluateRedshift,
		"AWS::Cognito::UserPool":  e.evaluateCognito,
		"AWS::Lambda::Function":   e.evaluateLambda,
		"AWS::S3::Bucket":         e.evaluateS3,
		"AWS::SNS::Topic":         e.evaluateSNS,
		"AWS::SQS::Queue":         e.evaluateSQS,
		"AWS::EFS::FileSystem":    e.evaluateEFS,
		"AWS::EC2::Image":         e.evaluateEC2Image,
		"AWS::ElasticLoadBalancingV2::LoadBalancer": e.evaluateELBv2,
		"AWS::ElasticLoadBalancing::LoadBalancer":   e.evaluateELBv2,
		"AWS::AppRunner::Service":                   e.evaluateAppRunner,
		"AWS::CloudFront::Distribution":             e.evaluateCloudFront,
		"AWS::GlobalAccelerator::Accelerator":       e.evaluateGlobalAccelerator,
		"AWS::ElasticBeanstalk::Environment":        e.evaluateElasticBeanstalk,
		"AWS::Transfer::Server":                     e.evaluateTransfer,
		"AWS::AppSync::GraphQLApi":                  e.evaluateAppSync,
		"AWS::OpenSearchService::Domain":            e.evaluateOpenSearch,
		"AWS::EKS::Cluster":                         e.evaluateEKS,
		"AWS::ApiGateway::RestApi":                  e.evaluateAPIGatewayRest,
		"AWS::ApiGatewayV2::Api":                    e.evaluateAPIGatewayV2,
	}
}

// SupportedResourceTypes returns all resource types the evaluator handles.
func SupportedResourceTypes() []string {
	// Stable ordering — not derived from map iteration.
	return []string{
		"AWS::Amplify::App",
		"AWS::EC2::Instance",
		"AWS::S3::Bucket",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::Lambda::Function",
		"AWS::EFS::FileSystem",
		"AWS::Cognito::UserPool",
		"AWS::RDS::DBInstance",
		"AWS::Redshift::Cluster",
		"AWS::EC2::Image",
		"AWS::ElasticLoadBalancingV2::LoadBalancer",
		"AWS::ElasticLoadBalancing::LoadBalancer",
		"AWS::AppRunner::Service",
		"AWS::CloudFront::Distribution",
		"AWS::GlobalAccelerator::Accelerator",
		"AWS::ElasticBeanstalk::Environment",
		"AWS::Transfer::Server",
		"AWS::AppSync::GraphQLApi",
		"AWS::OpenSearchService::Domain",
		"AWS::EKS::Cluster",
		"AWS::ApiGateway::RestApi",
		"AWS::ApiGatewayV2::Api",
	}
}

// ResourceEvaluator evaluates AWS resources for public access using property
// inspection and policy evaluation.
type ResourceEvaluator struct {
	opts             plugin.AWSCommonRecon
	crossRegionActor *ratelimit.CrossRegionActor
	orgPolicies      *orgpolicies.OrgPolicies

	accountID     string
	accountIDOnce sync.Once
	accountIDErr  error
}

// NewResourceEvaluator creates a new ResourceEvaluator.
func NewResourceEvaluator(opts plugin.AWSCommonRecon, orgPolicies *orgpolicies.OrgPolicies) *ResourceEvaluator {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	return &ResourceEvaluator{
		opts:             opts,
		crossRegionActor: ratelimit.NewCrossRegionActor(concurrency),
		orgPolicies:      orgPolicies,
	}
}

// SupportedResourceTypes returns all resource types this evaluator handles.
func (e *ResourceEvaluator) SupportedResourceTypes() []string {
	return SupportedResourceTypes()
}

// Evaluate is a pipeline-compatible method that evaluates a single resource for
// public access and sends it downstream if public or needing triage.
func (e *ResourceEvaluator) Evaluate(resource output.AWSResource, out *pipeline.P[PublicAccessResult]) error {
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

		accountID, err := e.getAccountID(awsCfg)
		if err != nil {
			slog.Warn("failed to get account ID, skipping resource",
				"resource", resource.ResourceID, "region", resource.Region, "error", err)
			return nil
		}

		e.evaluateCore(&resource, awsCfg, accountID, out)
		return nil
	})
}

func (e *ResourceEvaluator) getAccountID(awsCfg aws.Config) (string, error) {
	e.accountIDOnce.Do(func() {
		e.accountID, e.accountIDErr = awshelpers.GetAccountId(awsCfg)
	})
	return e.accountID, e.accountIDErr
}

// evaluateCore performs the core evaluation logic: looks up the evaluator for
// the resource type, runs it, and sends public/triage results downstream.
func (e *ResourceEvaluator) evaluateCore(resource *output.AWSResource, awsCfg aws.Config, accountID string, out *pipeline.P[PublicAccessResult]) {
	if resource.Properties == nil {
		resource.Properties = make(map[string]any)
	}

	eval, ok := e.evaluators()[resource.ResourceType]
	if !ok {
		return
	}

	result := eval(resource, awsCfg, accountID)
	if result == nil {
		result = &PublicAccessResult{}
	}

	switch {
	case result.NeedsManualTriage:
		resource.AccessLevel = output.AccessLevelNeedsTriage
	case result.IsPublic:
		resource.AccessLevel = output.AccessLevelPublic
	default:
		resource.AccessLevel = output.AccessLevelPrivate
	}

	result.AWSResource = resource
	out.Send(*result)
}

// --- property-based evaluators ---

func (e *ResourceEvaluator) evaluateAmplify(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	if len(resource.URLs) == 0 {
		return nil
	}

	defaultDomain, _ := resource.Properties["DefaultDomain"].(string)
	appName, _ := resource.Properties["Name"].(string)
	label := cmp.Or(appName, defaultDomain, resource.ResourceID)

	return &PublicAccessResult{
		IsPublic:       true,
		AllowedActions: []string{"amplify:GetApp"},
		EvaluationReasons: []string{
			fmt.Sprintf("Amplify app '%s' has %d publicly accessible branch URL(s)", label, len(resource.URLs)),
		},
	}
}

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

func (e *ResourceEvaluator) evaluateRedshift(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	isPublic, _ := resource.Properties["IsPubliclyAccessible"].(bool)
	if !isPublic {
		return nil
	}
	return &PublicAccessResult{
		IsPublic: true,
		EvaluationReasons: []string{
			"Redshift cluster is publicly accessible (PubliclyAccessible=true)",
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

func (e *ResourceEvaluator) evaluateEC2Image(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	isPublic, _ := resource.Properties["IsPublic"].(bool)
	if !isPublic {
		return nil
	}

	instances, _ := resource.Properties["InUseByInstances"].([]string)
	if instances == nil {
		if raw, ok := resource.Properties["InUseByInstances"].([]any); ok {
			for _, v := range raw {
				if s, ok := v.(string); ok {
					instances = append(instances, s)
				}
			}
		}
	}

	imageID, _ := resource.Properties["ImageId"].(string)
	name, _ := resource.Properties["Name"].(string)

	if len(instances) > 0 {
		return &PublicAccessResult{
			IsPublic:       true,
			AllowedActions: []string{"ec2:DescribeImages", "ec2:RunInstances"},
			EvaluationReasons: []string{
				fmt.Sprintf("AMI '%s' (%s) is publicly accessible and in use by %d running instance(s)",
					name, imageID, len(instances)),
				"Attackers can launch instances from this AMI to extract credentials, SSH keys, and application code",
			},
		}
	}

	return &PublicAccessResult{
		NeedsManualTriage: true,
		AllowedActions:    []string{"ec2:DescribeImages", "ec2:RunInstances"},
		EvaluationReasons: []string{
			fmt.Sprintf("AMI '%s' (%s) is publicly accessible but not in use by any running instances",
				name, imageID),
			"While not actively deployed, the AMI may contain sensitive data; recommend removing public access",
		},
	}
}

func (e *ResourceEvaluator) evaluateELBv2(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	internetFacing, _ := resource.Properties["IsInternetFacing"].(bool)
	if !internetFacing {
		return nil
	}
	name, _ := resource.Properties["LoadBalancerName"].(string)
	label := cmp.Or(name, resource.ResourceID)
	return &PublicAccessResult{
		IsPublic:          true,
		NeedsManualTriage: true,
		AllowedActions:    []string{"elasticloadbalancing:NetworkAccess"},
		EvaluationReasons: []string{
			fmt.Sprintf("Load balancer '%s' is internet-facing (Scheme=internet-facing); listeners, target groups, and any authentication require manual review", label),
		},
	}
}

func (e *ResourceEvaluator) evaluateAppRunner(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	isPublic, _ := resource.Properties["IsPubliclyAccessible"].(bool)
	if !isPublic {
		return nil
	}
	serviceURL, _ := resource.Properties["ServiceUrl"].(string)
	reason := "App Runner service accepts public ingress (NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible=true)"
	if serviceURL != "" {
		reason = fmt.Sprintf("%s at %s", reason, serviceURL)
	}
	return &PublicAccessResult{
		IsPublic:          true,
		NeedsManualTriage: true,
		AllowedActions:    []string{"apprunner:NetworkAccess"},
		EvaluationReasons: []string{reason},
	}
}

func (e *ResourceEvaluator) evaluateCloudFront(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	enabled, _ := resource.Properties["DistributionEnabled"].(bool)
	if !enabled {
		return nil
	}
	hasWAF, _ := resource.Properties["HasWebACL"].(bool)
	reason := "CloudFront distribution is internet-facing"
	if hasWAF {
		reason += " and has a WAF web ACL attached; review origin access and cache behaviors"
	} else {
		reason += " with no WAF web ACL attached; review origin access, cache behaviors, and consider attaching a WAF"
	}
	return &PublicAccessResult{
		IsPublic:          true,
		NeedsManualTriage: true,
		AllowedActions:    []string{"cloudfront:NetworkAccess"},
		EvaluationReasons: []string{reason},
	}
}

func (e *ResourceEvaluator) evaluateGlobalAccelerator(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	enabled, _ := resource.Properties["Enabled"].(bool)
	if !enabled {
		return nil
	}
	return &PublicAccessResult{
		IsPublic:          true,
		NeedsManualTriage: true,
		AllowedActions:    []string{"globalaccelerator:NetworkAccess"},
		EvaluationReasons: []string{
			"Global Accelerator is enabled and routes internet traffic to backend endpoints; review listeners and endpoint groups",
		},
	}
}

func (e *ResourceEvaluator) evaluateElasticBeanstalk(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	endpointURL, _ := resource.Properties["EndpointURL"].(string)
	if endpointURL == "" {
		return nil
	}
	return &PublicAccessResult{
		IsPublic:          true,
		NeedsManualTriage: true,
		AllowedActions:    []string{"elasticbeanstalk:NetworkAccess"},
		EvaluationReasons: []string{
			fmt.Sprintf("Elastic Beanstalk environment exposes endpoint %s; review the fronting load balancer and application authentication", endpointURL),
		},
	}
}

func (e *ResourceEvaluator) evaluateTransfer(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	endpointType, _ := resource.Properties["EndpointType"].(string)
	if endpointType != "PUBLIC" {
		return nil
	}
	return &PublicAccessResult{
		NeedsManualTriage: true,
		AllowedActions:    []string{"transfer:NetworkAccess"},
		EvaluationReasons: []string{
			"Transfer Family server has a PUBLIC endpoint reachable from the internet; access is gated by the server's identity provider (SSH key, password, or custom IdP), which requires manual review",
		},
	}
}

func (e *ResourceEvaluator) evaluateAppSync(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	via := ""
	if primary, _ := resource.Properties["AuthenticationType"].(string); primary == "API_KEY" {
		via = "primary authentication"
	} else if appSyncHasAPIKeyProvider(resource.Properties["AdditionalAuthenticationProviders"]) {
		via = "an additional authentication provider"
	}
	if via == "" {
		return nil
	}
	return &PublicAccessResult{
		IsPublic:          true,
		NeedsManualTriage: true,
		AllowedActions:    []string{"appsync:GraphQL"},
		EvaluationReasons: []string{
			fmt.Sprintf("AppSync GraphQL API accepts API_KEY authentication via %s; any holder of an API key can call the full GraphQL schema", via),
		},
	}
}

// appSyncHasAPIKeyProvider reports whether any entry in an AppSync
// AdditionalAuthenticationProviders list uses API_KEY. A non-API_KEY primary
// auth type does not preclude an additional API_KEY provider.
func appSyncHasAPIKeyProvider(raw any) bool {
	providers, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, p := range providers {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := m["AuthenticationType"].(string); t == "API_KEY" {
			return true
		}
	}
	return false
}

func (e *ResourceEvaluator) evaluateOpenSearch(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	fgacEnabled, _ := resource.Properties["FGACEnabled"].(bool)
	if fgacEnabled {
		return nil
	}
	// With FGAC disabled the access policy is the only authorization layer. A
	// restrictive policy still gates the domain, so only flag when the policy
	// grants a wildcard principal (no identity required).
	wildcard, _ := resource.Properties["HasWildcardAccessPolicy"].(bool)
	if !wildcard {
		return nil
	}
	reach := "any client that can reach the domain's public endpoint over the internet"
	if vpcScoped, _ := resource.Properties["VPCScoped"].(bool); vpcScoped {
		reach = "any client within the domain's VPC"
	}
	return &PublicAccessResult{
		NeedsManualTriage: true,
		AllowedActions:    []string{"es:ESHttpGet"},
		EvaluationReasons: []string{
			fmt.Sprintf("OpenSearch/Elasticsearch domain has fine-grained access control disabled and an access policy granting a wildcard principal; %s can call the domain with no credentials", reach),
		},
	}
}

func (e *ResourceEvaluator) evaluateEKS(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	publicAccess, _ := resource.Properties["EndpointPublicAccess"].(bool)
	if !publicAccess {
		return nil
	}
	openToInternet, _ := resource.Properties["PublicAccessOpenToInternet"].(bool)
	reason := "EKS cluster API server endpoint is publicly accessible but restricted to specific CIDRs; review the allowed ranges"
	if openToInternet {
		reason = "EKS cluster API server endpoint is publicly accessible from the entire internet (PublicAccessCidrs includes 0.0.0.0/0 or ::/0); the endpoint still requires Kubernetes/IAM authentication, which requires manual review"
	}
	return &PublicAccessResult{
		NeedsManualTriage: true,
		AllowedActions:    []string{"eks:NetworkAccess"},
		EvaluationReasons: []string{reason},
	}
}

func (e *ResourceEvaluator) evaluateAPIGatewayRest(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	// A PRIVATE REST API is reachable only from within the VPC via an interface
	// endpoint, so NONE-auth methods are not internet-exposed.
	if apiGatewayIsPrivate(resource.Properties["EndpointConfiguration"]) {
		return nil
	}
	unauth, _ := resource.Properties["UnauthenticatedMethodCount"].(int)
	if unauth <= 0 {
		return nil
	}
	// A resource policy can restrict invocation (source IP, VPC endpoint, account)
	// independently of method authorization. Its presence means access cannot be
	// confirmed open from configuration alone, so report for triage rather than
	// asserting public.
	if hasNonEmptyResourcePolicy(resource.Properties["Policy"]) {
		return &PublicAccessResult{
			NeedsManualTriage: true,
			AllowedActions:    []string{"execute-api:Invoke"},
			EvaluationReasons: []string{
				fmt.Sprintf("REST API has %d method(s) with AuthorizationType NONE and no API key, but a resource policy is attached; review whether the policy restricts invocation", unauth),
			},
		}
	}
	return &PublicAccessResult{
		NeedsManualTriage: true,
		AllowedActions:    []string{"execute-api:Invoke"},
		EvaluationReasons: []string{
			fmt.Sprintf("REST API has %d method(s) with AuthorizationType NONE and no API key required; confirm the API is deployed to a reachable stage with the default execute-api endpoint enabled", unauth),
		},
	}
}

// apiGatewayIsPrivate reports whether a REST API's EndpointConfiguration.Types
// contains PRIVATE (reachable only via a VPC interface endpoint).
func apiGatewayIsPrivate(raw any) bool {
	cfg, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	types, ok := cfg["Types"].([]any)
	if !ok {
		return false
	}
	for _, t := range types {
		if s, _ := t.(string); s == "PRIVATE" {
			return true
		}
	}
	return false
}

// hasNonEmptyResourcePolicy reports whether a resource policy is attached. The
// policy is returned by CloudControl as a string or a decoded map depending on
// the resource type.
func hasNonEmptyResourcePolicy(raw any) bool {
	switch v := raw.(type) {
	case string:
		return v != "" && v != "null"
	case map[string]any:
		return len(v) > 0
	default:
		return false
	}
}

func (e *ResourceEvaluator) evaluateAPIGatewayV2(resource *output.AWSResource, _ aws.Config, _ string) *PublicAccessResult {
	unauth, _ := resource.Properties["UnauthenticatedRouteCount"].(int)
	if unauth <= 0 {
		return nil
	}
	return &PublicAccessResult{
		NeedsManualTriage: true,
		AllowedActions:    []string{"execute-api:Invoke"},
		EvaluationReasons: []string{
			fmt.Sprintf("HTTP/WebSocket API has %d route(s) with AuthorizationType NONE; confirm the API is deployed to a reachable stage with the default execute-api endpoint enabled", unauth),
		},
	}
}

// --- policy-based evaluators ---

func (e *ResourceEvaluator) evaluateS3(resource *output.AWSResource, awsCfg aws.Config, accountID string) *PublicAccessResult {
	client := s3.NewFromConfig(awsCfg)
	policy, err := resourcepolicies.FetchS3BucketPolicyExtended(context.Background(), client, resource, e.opts.Regions)
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

	result, err := evaluateResourcePolicy(policy, resourceARN, accountID, resource.ResourceType, e.orgPolicies)
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
