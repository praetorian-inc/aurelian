package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
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
	policy, err := u.getPolicy(context.TODO(), awsCfg, serviceConfig, identifierStr)
	if err != nil {
		slog.Debug("Failed to get policy", "resource", identifierStr, "type", resource.TypeName, "error", err)
		return nil // Continue with other resources
	}

	// Skip if no policy
	if policy == "" {
		return nil
	}

	// Check if the policy allows public access
	isPublic, err := analyzePolicy(resource.Arn.String(), policy)
	if err != nil {
		slog.Error("Failed to analyze policy", "resource", identifierStr, "error", err)
		return err
	}

	// Skip if not public
	if !isPublic {
		return nil
	}

	// Add the policy to the properties
	props[serviceConfig.PolicyField] = policy

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

// getPolicy retrieves a policy using reflection to handle different service clients
func (u *AwsResourcePolicyChecker) getPolicy(ctx context.Context, cfg aws.Config, serviceConfig ServicePolicyConfig, identifier string) (string, error) {
	// Create the client
	client := serviceConfig.ClientConstructor(cfg)
	clientValue := reflect.ValueOf(client)

	// Create the input
	input := serviceConfig.InputConstructor(identifier)

	// Find the appropriate method (GetBucketPolicy, GetTopicAttributes, etc.)
	// The method name is derived from the input type name
	inputType := reflect.TypeOf(input).Elem()
	methodName := strings.TrimSuffix(inputType.Name(), "Input")
	method := clientValue.MethodByName(methodName)

	if !method.IsValid() {
		return "", fmt.Errorf("method %s not found on client", methodName)
	}

	// Call the method
	results := method.Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(input),
	})

	// Check for error
	if !results[1].IsNil() {
		err := results[1].Interface().(error)
		// Handle "no policy" errors gracefully
		if strings.Contains(err.Error(), "NoSuchBucketPolicy") ||
			strings.Contains(err.Error(), "NoSuchEntityException") ||
			strings.Contains(err.Error(), "ResourceNotFoundException") {
			return "", nil
		}
		return "", err
	}

	// Extract the policy using the field path
	return extractPolicy(results[0].Interface(), serviceConfig.GetPolicyFieldPath)
}

// extractPolicy extracts a policy string from a response using a dot-notation path
func extractPolicy(response interface{}, path string) (string, error) {
	parts := strings.Split(path, ".")
	value := reflect.ValueOf(response)

	for _, part := range parts {
		// Handle pointer indirection
		if value.Kind() == reflect.Ptr && !value.IsNil() {
			value = value.Elem()
		}

		// Handle map access
		if value.Kind() == reflect.Map {
			mapValue := value.MapIndex(reflect.ValueOf(part))
			if !mapValue.IsValid() {
				return "", nil // Field not found
			}
			value = mapValue
			continue
		}

		// Handle struct field access
		if value.Kind() == reflect.Struct {
			value = value.FieldByName(part)
			if !value.IsValid() {
				return "", nil // Field not found
			}
			continue
		}

		return "", fmt.Errorf("cannot access %s in %v", part, value.Type())
	}

	// Handle final pointer indirection
	if value.Kind() == reflect.Ptr && !value.IsNil() {
		value = value.Elem()
	}

	// Get the string value
	if value.Kind() == reflect.String {
		return value.String(), nil
	}

	return "", fmt.Errorf("path %s does not lead to a string", path)
}

// analyzePolicy analyzes a policy to determine if it grants public access
func analyzePolicy(resource, policyStr string) (bool, error) {
	var policy types.Policy
	err := json.Unmarshal([]byte(policyStr), &policy)
	if err != nil {
		return false, err
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
			return false, err
		}

		slog.Debug("Policy evaluation result", "resource", resource, "action", action, "allowed", res.Allowed, "EvaluationResult", res)

		// shortcut if the action is allowed
		if res.Allowed {
			return true, nil
		}
	}

	return false, nil
}

type ServicePolicyConfig struct {
	// ClientConstructor creates a service client from an AWS config
	ClientConstructor func(cfg aws.Config) interface{}

	// InputConstructor creates the appropriate input type for the GetPolicy method
	InputConstructor func(identifier string) interface{}

	// GetPolicyFieldPath is the JSON path to extract the policy from the response
	// e.g., "Policy" for SQS/SNS, "PolicyDocument" for IAM
	GetPolicyFieldPath string

	// IdentifierField is the name of the field in ResourceDescription.Properties to use as identifier
	IdentifierField string

	// PolicyField is the name of the field to store the policy in the output
	PolicyField string
}

// ServiceMap maps AWS resource types to their policy checking configurations
var ServiceMap = map[string]ServicePolicyConfig{
	// Example mappings
	"AWS::S3::Bucket": {
		ClientConstructor: func(cfg aws.Config) interface{} {
			return s3.NewFromConfig(cfg)
		},
		InputConstructor: func(id string) interface{} {
			return &s3.GetBucketPolicyInput{Bucket: aws.String(id)}
		},
		GetPolicyFieldPath: "Policy",
		IdentifierField:    "BucketName",
		PolicyField:        "AccessPolicy",
	},
	"AWS::SNS::Topic": {
		ClientConstructor: func(cfg aws.Config) interface{} {
			return sns.NewFromConfig(cfg)
		},
		InputConstructor: func(id string) interface{} {
			return &sns.GetTopicAttributesInput{TopicArn: aws.String(id)}
		},
		GetPolicyFieldPath: "Attributes.Policy",
		IdentifierField:    "TopicArn",
		PolicyField:        "AccessPolicy",
	},
	"AWS::SQS::Queue": {
		ClientConstructor: func(cfg aws.Config) interface{} {
			return sqs.NewFromConfig(cfg)
		},
		InputConstructor: func(id string) interface{} {
			return &sqs.GetQueueAttributesInput{
				QueueUrl:       aws.String(id),
				AttributeNames: []sqstypes.QueueAttributeName{"Policy"},
			}
		},
		GetPolicyFieldPath: "Attributes.Policy",
		IdentifierField:    "QueueUrl",
		PolicyField:        "AccessPolicy",
	},
	"AWS::Lambda::Function": {
		ClientConstructor: func(cfg aws.Config) interface{} {
			return lambda.NewFromConfig(cfg)
		},
		InputConstructor: func(id string) interface{} {
			return &lambda.GetPolicyInput{FunctionName: aws.String(id)}
		},
		GetPolicyFieldPath: "Policy",
		IdentifierField:    "FunctionName",
		PolicyField:        "AccessPolicy",
	},
	"AWS::EFS::FileSystem": {
		ClientConstructor: func(cfg aws.Config) interface{} {
			return efs.NewFromConfig(cfg)
		},
		InputConstructor: func(id string) interface{} {
			return &efs.DescribeFileSystemPolicyInput{FileSystemId: aws.String(id)}
		},
		GetPolicyFieldPath: "Policy",
		IdentifierField:    "FileSystemId",
		PolicyField:        "AccessPolicy",
	},
	"AWS::ElasticSearch::Domain": {
		ClientConstructor: func(cfg aws.Config) interface{} {
			return elasticsearchservice.NewFromConfig(cfg)
		},
		InputConstructor: func(id string) interface{} {
			return &elasticsearchservice.DescribeElasticsearchDomainConfigInput{DomainName: aws.String(id)}
		},
		GetPolicyFieldPath: "DomainConfig.AccessPolicies",
		IdentifierField:    "DomainName",
		PolicyField:        "AccessPolicy",
	},
}
