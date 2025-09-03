package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	iam "github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsResourcePolicyChecker struct {
	*base.AwsReconLink
	orgPolicies *orgpolicies.OrgPolicies
}

func NewAwsResourcePolicyChecker(configs ...cfg.Config) chain.Link {
	r := &AwsResourcePolicyChecker{}
	r.AwsReconLink = base.NewAwsReconLink(r, configs...)
	return r
}

func (a *AwsResourcePolicyChecker) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsOrgPoliciesFile())
	return params
}

func (a *AwsResourcePolicyChecker) Initialize() error {
	if err := a.AwsReconLink.Initialize(); err != nil {
		return err
	}

	// Load org policies if file is provided
	orgPoliciesFile, _ := cfg.As[string](a.Arg("org-policies"))
	if orgPoliciesFile != "" {
		slog.Debug("Loading organization policies", "file", orgPoliciesFile)
		orgPolicies, err := loadOrgPoliciesFromFile(orgPoliciesFile)
		if err != nil {
			slog.Error("Failed to load org policies", "file", orgPoliciesFile, "error", err)
			return fmt.Errorf("failed to load org policies from %s: %w", orgPoliciesFile, err)
		}
		a.orgPolicies = orgPolicies
		slog.Info("Successfully loaded organization policies", "file", orgPoliciesFile, "scps", len(orgPolicies.SCPs), "rcps", len(orgPolicies.RCPs))
	}

	return nil
}

// loadOrgPoliciesFromFile loads organization policies from a JSON file
func loadOrgPoliciesFromFile(filePath string) (*orgpolicies.OrgPolicies, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var orgPolicies orgpolicies.OrgPolicies
	if err := json.Unmarshal(data, &orgPolicies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &orgPolicies, nil
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

	policyJson, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		slog.Debug(fmt.Sprintf("policy for %s (failed to marshal): %v", resource.Arn.String(), err))
	} else {
		slog.Debug(fmt.Sprintf("policy for %s", resource.Arn.String()), "policy", string(policyJson))
	}

	// Check if the policy allows public access
	res, err := a.analyzePolicy(resource.Arn.String(), policy, resource.AccountId, resource.TypeName)
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

// ConditionPermutation represents a condition key and its possible values
type ConditionPermutation struct {
	Key    string
	Values []string // Include "" for missing/absent
}

// ContextGenerator generates comprehensive context permutations for testing
type ContextGenerator struct {
	BasePrincipals []string
	Conditions     []ConditionPermutation
}

// Bool helper function for creating *bool values
func Bool(b bool) *bool {
	return &b
}

// GenerateAllPermutations creates all combinations of contexts with condition permutations
func (cg *ContextGenerator) GenerateAllPermutations() []*iam.RequestContext {
	contexts := []*iam.RequestContext{}

	// Add base principal contexts first (existing behavior)
	for _, principal := range cg.BasePrincipals {
		ctx := &iam.RequestContext{
			PrincipalArn:      principal,
			RequestParameters: make(map[string]string),
		}
		contexts = append(contexts, ctx)
	}

	// Generate all condition combinations for wildcard principal
	permutations := cg.generateConditionPermutations()

	for _, perm := range permutations {
		ctx := &iam.RequestContext{
			PrincipalArn:      "*", // Wildcard for public access testing
			RequestParameters: make(map[string]string),
		}

		cg.applyPermutation(ctx, perm)
		contexts = append(contexts, ctx)
	}

	return contexts
}

// generateConditionPermutations creates all combinations of condition values
func (cg *ContextGenerator) generateConditionPermutations() []map[string]string {
	if len(cg.Conditions) == 0 {
		return []map[string]string{{}}
	}

	// Calculate total permutations
	totalPerms := 1
	for _, condition := range cg.Conditions {
		totalPerms *= len(condition.Values)
	}

	permutations := make([]map[string]string, totalPerms)

	// Generate all combinations
	for i := 0; i < totalPerms; i++ {
		perm := make(map[string]string)
		temp := i

		for _, condition := range cg.Conditions {
			valueIndex := temp % len(condition.Values)
			value := condition.Values[valueIndex]
			if value != "" { // Only include non-empty values
				perm[condition.Key] = value
			}
			temp /= len(condition.Values)
		}

		permutations[i] = perm
	}

	return permutations
}

// applyPermutation applies condition values to a RequestContext
func (cg *ContextGenerator) applyPermutation(ctx *iam.RequestContext, perm map[string]string) {
	for key, value := range perm {
		switch key {
		// Direct RequestContext fields
		case "aws:SecureTransport":
			if value == "true" {
				ctx.SecureTransport = Bool(true)
			} else if value == "false" {
				ctx.SecureTransport = Bool(false)
			}
		case "aws:PrincipalType":
			ctx.PrincipalType = value
		case "aws:SourceAccount":
			ctx.SourceAccount = value
		case "aws:SourceVpc":
			ctx.SourceVPC = value
		case "aws:SourceArn":
			ctx.SourceArn = value
		case "aws:PrincipalOrgID":
			ctx.PrincipalOrgID = value

		// RequestParameters (service-specific keys)
		default:
			ctx.RequestParameters[key] = value
		}
	}
}

// GetEvaluationContexts returns comprehensive RequestContexts for testing different access scenarios
func GetEvaluationContexts(resourceType string) []*iam.RequestContext {
	switch resourceType {
	case "AWS::Lambda::Function":
		generator := ContextGenerator{
			BasePrincipals: []string{
				"arn:aws:iam::111122223333:role/praetorian", // Generic cross-account
				"apigateway.amazonaws.com",                  // API Gateway service
				"lambda.amazonaws.com",                      // Lambda service
			},
			Conditions: []ConditionPermutation{
				{"lambda:FunctionUrlAuthType", []string{"NONE", "AWS_IAM", ""}},
				{"aws:SecureTransport", []string{"true", "false", ""}},
				{"aws:PrincipalType", []string{"Anonymous", "AssumedRole", "User", "Service", ""}},
				{"aws:SourceAccount", []string{"111122223333", ""}},
			},
		}
		return generator.GenerateAllPermutations()

	case "AWS::S3::Bucket":
		generator := ContextGenerator{
			BasePrincipals: []string{
				"arn:aws:iam::111122223333:role/praetorian", // Generic cross-account
				"cloudfront.amazonaws.com",                  // CloudFront service
				"s3.amazonaws.com",                          // S3 service
			},
			Conditions: []ConditionPermutation{
				{"aws:SecureTransport", []string{"true", "false", ""}},
				{"aws:PrincipalType", []string{"Anonymous", "AssumedRole", "User", ""}},
				{"s3:x-amz-server-side-encryption", []string{"AES256", "aws:kms", ""}},
				{"aws:SourceAccount", []string{"111122223333", ""}},
				{"aws:SourceVpc", []string{"vpc-12345678", ""}},
				{"aws:SourceVpce", []string{"vpce-0123abcd4ef567890", ""}},
			},
		}
		return generator.GenerateAllPermutations()

	case "AWS::SNS::Topic":
		generator := ContextGenerator{
			BasePrincipals: []string{
				"arn:aws:iam::111122223333:role/praetorian",
				"sns.amazonaws.com",
			},
			Conditions: []ConditionPermutation{
				{"aws:SecureTransport", []string{"true", "false", ""}},
				{"aws:PrincipalType", []string{"Anonymous", "AssumedRole", "User", ""}},
				{"aws:SourceAccount", []string{"111122223333", ""}},
			},
		}
		return generator.GenerateAllPermutations()

	case "AWS::SQS::Queue":
		generator := ContextGenerator{
			BasePrincipals: []string{
				"arn:aws:iam::111122223333:role/praetorian",
				"sqs.amazonaws.com",
				"sns.amazonaws.com", // SNS can send to SQS
			},
			Conditions: []ConditionPermutation{
				{"aws:SecureTransport", []string{"true", "false", ""}},
				{"aws:PrincipalType", []string{"Anonymous", "AssumedRole", "User", ""}},
				{"aws:SourceAccount", []string{"111122223333", ""}},
				{"aws:SourceArn", []string{"arn:aws:sns:*:111122223333:*", ""}},
			},
		}
		return generator.GenerateAllPermutations()

	default:
		// Default fallback for unknown resource types
		return []*iam.RequestContext{
			{PrincipalArn: "arn:aws:iam::111122223333:role/praetorian"},
		}
	}
}

// evaluatePolicyWithContext evaluates a policy with a specific RequestContext (DRY helper)
func (a *AwsResourcePolicyChecker) evaluatePolicyWithContext(reqCtx *iam.RequestContext, policy *types.Policy, resource string) ([]*iam.EvaluationResult, error) {
	pd := iam.NewPolicyData(
		nil,           // GAAD - not needed for resource policy analysis
		a.orgPolicies, // Organization policies from loaded file
		map[string]*types.Policy{
			resource: policy,
		},
		nil, // Resources - not needed for this analysis
	)

	evaluator := iam.NewPolicyEvaluator(pd)

	if policy.Statement == nil {
		return nil, errors.New("policy statement is nil")
	}

	results := []*iam.EvaluationResult{}
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
			return nil, err
		}

		slog.Debug("Policy evaluation result", "principal", reqCtx.PrincipalArn, "resource", resource, "action", action, "allowed", res.Allowed, "EvaluationResult", res)
		results = append(results, res)
	}

	return results, nil
}

// analyzePolicy analyzes a policy to determine if it grants public access
func (a *AwsResourcePolicyChecker) analyzePolicy(resource string, policy *types.Policy, accountId string, resourceType string) ([]*iam.EvaluationResult, error) {
	allResults := []*iam.EvaluationResult{}

	contexts := GetEvaluationContexts(resourceType)

	for _, reqCtx := range contexts {
		// Apply org policies context if available
		if a.orgPolicies != nil && accountId != "" {
			reqCtx.ResourceAccount = accountId
			slog.Debug("Enhanced policy analysis with org policies", "resource", resource, "account", accountId, "principal", reqCtx.PrincipalArn, "org_policies_available", true)
		}
		reqCtx.PopulateDefaultRequestConditionKeys(resource)

		// Evaluate policy with this context
		results, err := a.evaluatePolicyWithContext(reqCtx, policy, resource)
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)
	}

	return allResults, nil
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
	actionSet := make(map[string]struct{})
	actions := []string{}
	for _, res := range allowed {
		actionStr := string(res.Action)
		if _, exists := actionSet[actionStr]; !exists {
			actionSet[actionStr] = struct{}{}
			actions = append(actions, actionStr)
		}
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

		// 0. Check bucket location first to ensure we're using the correct region
		locationResp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			slog.Error("Failed to get bucket location", "bucket", bucketName, "error", err)
			return nil, err
		}

		// Handle empty LocationConstraint (means us-east-1)
		bucketRegion := "us-east-1"
		if locationResp.LocationConstraint != "" {
			bucketRegion = string(locationResp.LocationConstraint)
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

		// 1. Check Block Public Access settings - if it blocks access, the request is denied regardless of policies or ACLs
		blockPublicAccessResp, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			// Log the error but continue - some buckets might not have public access block settings
			slog.Debug("Failed to get public access block settings", "bucket", bucketName, "error", err)
		} else if blockPublicAccessResp.PublicAccessBlockConfiguration != nil {
			config := blockPublicAccessResp.PublicAccessBlockConfiguration
			// Only check the two flags that actually block current access:
			// - IgnorePublicAcls: blocks all ACL-based public access
			// - RestrictPublicBuckets: blocks all policy-based public access
			// Note: BlockPublicAcls and BlockPublicPolicy only prevent future changes, not current access
			if (config.IgnorePublicAcls != nil && *config.IgnorePublicAcls) ||
				(config.RestrictPublicBuckets != nil && *config.RestrictPublicBuckets) {
				slog.Debug("Bucket has public access blocked", "bucket", bucketName,
					"ignorePublicAcls", config.IgnorePublicAcls != nil && *config.IgnorePublicAcls,
					"restrictPublicBuckets", config.RestrictPublicBuckets != nil && *config.RestrictPublicBuckets)

				// Create a policy that represents the blocked access
				// Use the correct types for Principal, Action, Resource, and Condition
				starPrincipal := types.DynaString{"*"}
				actionDynaString := types.DynaString{"s3:*"}
				resourceDynaString := types.DynaString{fmt.Sprintf("arn:aws:s3:::%s", bucketName), fmt.Sprintf("arn:aws:s3:::%s/*", bucketName)}

				// Essentiall we just return a virtual policy that denies everything
				blockStatement := types.PolicyStatement{
					Sid:       "VirtualPolicyFromBlockPublicAccess",
					Effect:    "Deny",
					Principal: &types.Principal{AWS: &starPrincipal},
					Action:    &actionDynaString,
					Resource:  &resourceDynaString,
				}

				blockStatementList := types.PolicyStatementList{blockStatement}
				return &types.Policy{
					Version:   "2012-10-17",
					Statement: &blockStatementList,
				}, nil
			}
		}

		// 2. We pass through the bucket policy since this is what we want from this function
		var bucketPolicy *types.Policy
		resp, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			if strings.Contains(err.Error(), "NoSuchBucketPolicy") {
				slog.Debug("Bucket does not exists", "bucket", bucketName, "error", err)
				return nil, err
			}
			slog.Debug("Failed to get bucket policy", "bucket", bucketName, "error", err)
			// Continue since we need to evaluate bucket ACL
		}
		if resp.Policy != nil {
			bucketPolicy, err = strToPolicy(*resp.Policy)
			if err != nil {
				slog.Debug("Error in converting string to policy, continuing to evaluate ACLs", "policy", *resp.Policy, "error", err)
			}
		}

		// 3. ACLs are evaluated last and can provide additional access controls
		// In this case, we merge the policies.
		// No better way to do this at the moment unless we evaluate the policy in the combined function with other resources
		aclResp, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			// Log ACL check failure but don't fail the entire operation
			slog.Debug("Failed to get bucket ACL", "bucket", bucketName, "error", err)
		} else if aclResp.Grants != nil {
			// Convert ACL grants to policy statements and merge with bucket policy
			aclStatements := convertACLGrantsToStatements(aclResp.Grants, bucketName)
			if len(aclStatements) > 0 {
				if bucketPolicy == nil {
					// Create a new policy if none exists
					aclStatementList := types.PolicyStatementList(aclStatements)
					bucketPolicy = &types.Policy{
						Version:   "2012-10-17",
						Statement: &aclStatementList,
					}
				} else {
					// Merge ACL statements with existing policy
					if bucketPolicy.Statement == nil {
						aclStatementList := types.PolicyStatementList(aclStatements)
						bucketPolicy.Statement = &aclStatementList
					} else {
						// Dereference, append, and reassign
						existingStatements := *bucketPolicy.Statement
						mergedStatements := append(existingStatements, aclStatements...)
						bucketPolicy.Statement = &mergedStatements
					}
				}
				slog.Debug("Merged ACL grants into bucket policy", "bucket", bucketName, "aclStatements", len(aclStatements))
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

// convertACLGrantsToStatements converts S3 ACL grants to IAM policy statements
func convertACLGrantsToStatements(grants []s3types.Grant, bucketName string) []types.PolicyStatement {
	var statements []types.PolicyStatement

	for _, grant := range grants {
		if grant.Grantee == nil || grant.Grantee.URI == nil {
			continue
		}

		// Map ACL permissions to IAM actions
		var actions []string
		switch grant.Permission {
		case "READ":
			actions = []string{
				"s3:GetObject",
				"s3:GetObjectVersion",
				"s3:ListBucket",
			}
		case "WRITE":
			actions = []string{
				"s3:PutObject",
				"s3:DeleteObject",
			}
		case "READ_ACP":
			actions = []string{"s3:GetBucketAcl"}
		case "WRITE_ACP":
			actions = []string{"s3:PutBucketAcl"}
		case "FULL_CONTROL":
			actions = []string{"s3:*"}
		default:
			continue
		}

		// Map grantee URI to principal
		var principal *types.Principal
		var granteeType string
		switch *grant.Grantee.URI {
		case "http://acs.amazonaws.com/groups/global/AllUsers":
			// Create a Principal with AWS field set to "*"
			star := types.DynaString{"*"}
			principal = &types.Principal{
				AWS: &star,
			}
			granteeType = "AllUsers"
		case "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
			// Create a Principal with AWS field set to "arn:aws:iam::*:root"
			authUsers := types.DynaString{"arn:aws:iam::*:root"}
			principal = &types.Principal{
				AWS: &authUsers,
			}
			granteeType = "AuthenticatedUsers"
		default:
			// Skip other grantee types for now
			continue
		}

		// Create statement with descriptive SID
		actionDynaString := types.DynaString(actions)
		resourceDynaString := types.DynaString{
			fmt.Sprintf("arn:aws:s3:::%s", bucketName),
			fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
		}
		statement := types.PolicyStatement{
			Sid:       fmt.Sprintf("VirtualPolicyFromACL-%s-%s", granteeType, grant.Permission),
			Effect:    "Allow",
			Principal: principal,
			Action:    &actionDynaString,
			Resource:  &resourceDynaString,
		}

		statements = append(statements, statement)
	}

	return statements
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
