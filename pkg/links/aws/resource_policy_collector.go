package aws

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
)

// PolicyWithArn wraps a policy with its associated resource ARN for keying
type PolicyWithArn struct {
	Policy      interface{} `json:"policy"`
	ResourceArn string      `json:"resource_arn"`
}

type AwsResourcePolicyCollector struct {
	*base.NativeAWSLink
}

func NewAwsResourcePolicyCollector(args map[string]any) *AwsResourcePolicyCollector {
	return &AwsResourcePolicyCollector{
		NativeAWSLink: base.NewNativeAWSLink("AwsResourcePolicyCollector", args),
	}
}

// Process implements the plugin interface
func (a *AwsResourcePolicyCollector) Process(ctx context.Context, input any) ([]any, error) {
	// TODO: Port Janus chain logic to standalone implementation
	a.Logger().Info("AwsResourcePolicyCollector.Process not yet implemented - requires Janus removal")
	return a.Outputs(), nil
}

// SupportedResourceTypes returns the AWS resource types that support resource policies
func (a *AwsResourcePolicyCollector) SupportedResourceTypes() []string {
	return []string{
		"AWS::S3::Bucket",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::KMS::Key",
		"AWS::Lambda::Function",
		"AWS::ECR::Repository",
		"AWS::ApiGateway::RestApi",
		"AWS::SecretsManager::Secret",
		"AWS::IAM::Role",
	}
}
