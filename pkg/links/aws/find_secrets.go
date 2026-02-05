package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/internal/message"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/cloudformation"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/cloudwatchlogs"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/ec2"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/ecr"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/lambda"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/stepfunctions"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSFindSecrets struct {
	*base.NativeAWSLink
	clientMap   map[string]interface{} // map key is type-region
}

func NewAWSFindSecrets(args map[string]any) *AWSFindSecrets {
	return &AWSFindSecrets{
		NativeAWSLink: base.NewNativeAWSLink("aws-find-secrets", args),
	}
}

func (fs *AWSFindSecrets) SupportedResourceTypes() []string {
	return []string{
		"AWS::EC2::Instance",
		"AWS::Lambda::Function",
		"AWS::CloudFormation::Stack",
		"AWS::Logs::LogGroup",
		"AWS::Logs::MetricFilter",
		"AWS::Logs::SubscriptionFilter",
		"AWS::Logs::Destination",
		"AWS::ECR::Repository",
		"AWS::ECS::TaskDefinition",
		"AWS::SSM::Document",
		"AWS::StepFunctions::StateMachine",
	}
}

func (fs *AWSFindSecrets) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}

	slog.Debug("Dispatching resource for processing", "resource_type", resource.TypeName, "resource_id", resource.Identifier)

	// Log max-events parameter tracking
	maxEvents := fs.ArgInt("max-events", 0)
	if maxEvents > 0 {
		message.Info("AWSFindSecrets passing max-events: resource_type=%s max_events_value=%d",
			resource.TypeName,
			maxEvents)
	}

	// Create args map for passing to sub-links
	// Include known parameters that sub-links may need
	args := map[string]any{
		"profile":     fs.Profile,
		"profile-dir": fs.ProfileDir,
		"regions":     fs.Regions,
		"max-events":  maxEvents,
	}

	// Process resource based on type
	// Each case represents the chain of operations that would have been in ResourceMap
	switch resource.TypeName {
	case "AWS::EC2::Instance":
		return ec2.NewAWSEC2UserData(args).Process(ctx, resource)

	case "AWS::Lambda::Function":
		return lambda.NewAWSLambdaFunctionCode(args).Process(ctx, resource)

	case "AWS::CloudFormation::Stack":
		return cloudformation.NewAWSCloudFormationTemplates(args).Process(ctx, resource)

	case "AWS::Logs::LogGroup", "AWS::Logs::MetricFilter", "AWS::Logs::SubscriptionFilter", "AWS::Logs::Destination":
		return cloudwatchlogs.NewAWSCloudWatchLogsEvents(args).Process(ctx, resource)

	case "AWS::ECR::Repository":
		// ECR processing chain: list images -> login -> download -> convert
		outputs, err := ecr.NewAWSECRListImages(args).Process(ctx, resource)
		if err != nil {
			return nil, err
		}
		// Further processing with docker and noseyparker would go here
		// when those links are migrated
		return outputs, nil

	case "AWS::ECS::TaskDefinition", "AWS::SSM::Document":
		// Direct noseyparker conversion (when noseyparker link is migrated)
		slog.Debug("Resource type needs noseyparker conversion", "type", resource.TypeName)
		return fs.Outputs(), nil

	case "AWS::StepFunctions::StateMachine":
		// Step Functions chain: list executions -> get details -> convert
		outputs, err := stepfunctions.NewAWSListExecutions(args).Process(ctx, resource)
		if err != nil {
			return nil, err
		}
		// Further processing with get execution details and noseyparker would go here
		return outputs, nil

	default:
		slog.Error("Unsupported resource type", "resource", resource)
		return nil, nil
	}
}
