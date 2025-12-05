package aws

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	janusDocker "github.com/praetorian-inc/janus-framework/pkg/links/docker"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudformation"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudwatchlogs"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ec2"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ecr"
	"github.com/praetorian-inc/nebula/pkg/links/aws/lambda"
	"github.com/praetorian-inc/nebula/pkg/links/aws/stepfunctions"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type AWSFindSecrets struct {
	*base.AwsReconLink
	clientMap   map[string]interface{} // map key is type-region
	resourceMap map[string]func() chain.Chain
}

func NewAWSFindSecrets(configs ...cfg.Config) chain.Link {
	fs := &AWSFindSecrets{}
	fs.AwsReconLink = base.NewAwsReconLink(fs, configs...)
	return fs
}

func (fs *AWSFindSecrets) Params() []cfg.Param {
	// Include max-events, max-streams and newest-first parameters so they can be received from module-level params
	params := fs.AwsReconLink.Params()
	params = append(params,
		cfg.NewParam[int]("max-events", "Maximum number of log events to fetch per log group/stream").WithDefault(10000),
		cfg.NewParam[int]("max-streams", "Maximum number of log streams to sample per log group").WithDefault(10),
		cfg.NewParam[bool]("newest-first", "Fetch newest events first instead of oldest").WithDefault(false),
	)
	return params
}

func (fs *AWSFindSecrets) Initialize() error {
	fs.AwsReconLink.Initialize()
	fs.resourceMap = fs.ResourceMap()
	return nil
}

func (fs *AWSFindSecrets) SupportedResourceTypes() []model.CloudResourceType {
	resources := fs.ResourceMap()
	types := make([]model.CloudResourceType, 0, len(resources))
	for resourceType := range resources {
		types = append(types, model.CloudResourceType(resourceType))
	}
	return types
}

func (fs *AWSFindSecrets) ResourceMap() map[string]func() chain.Chain {
	resourceMap := make(map[string]func() chain.Chain)

	resourceMap["AWS::EC2::Instance"] = func() chain.Chain {
		return chain.NewChain(
			ec2.NewAWSEC2UserData(),
		)
	}

	resourceMap["AWS::Lambda::Function"] = func() chain.Chain {
		return chain.NewChain(
			lambda.NewAWSLambdaFunctionCode(),
		)
	}

	resourceMap["AWS::CloudFormation::Stack"] = func() chain.Chain {
		return chain.NewChain(
			cloudformation.NewAWSCloudFormationTemplates(),
		)
	}

	resourceMap["AWS::Logs::LogGroup"] = func() chain.Chain {
		return chain.NewChain(
			cloudwatchlogs.NewAWSCloudWatchLogsEvents(),
		)
	}

	// AWS::Logs::LogStream is not supported by CloudControl API
	// LogStreams are discovered and processed inline when processing LogGroups

	resourceMap["AWS::Logs::MetricFilter"] = func() chain.Chain {
		return chain.NewChain(
			cloudwatchlogs.NewAWSCloudWatchLogsEvents(),
		)
	}

	// AWS::Logs::SubscriptionFilter is not currently enumerated in CloudControl
	// Keeping the chain definition in case it becomes available
	resourceMap["AWS::Logs::SubscriptionFilter"] = func() chain.Chain {
		return chain.NewChain(
			cloudwatchlogs.NewAWSCloudWatchLogsEvents(),
		)
	}

	resourceMap["AWS::Logs::Destination"] = func() chain.Chain {
		return chain.NewChain(
			cloudwatchlogs.NewAWSCloudWatchLogsEvents(),
		)
	}

	resourceMap["AWS::ECR::Repository"] = func() chain.Chain {
		return chain.NewChain(
			ecr.NewAWSECRListImages(),
			ecr.NewAWSECRLogin(),
			janusDocker.NewDockerDownload(),
			noseyparker.NewConvertToNPInput(),
		)
	}

	// resourceMap["AWS::ECR::PublicRepository"] = func() chain.Chain {
	// 	return chain.NewChain(
	// 		ecr.NewAWSECRListPublicImages(),
	// 		ecr.NewAWSECRLoginPublic(),
	// 		docker.NewDockerPull(),
	// 		docker.NewDockerSave(),
	// 		noseyparker.NewConvertToNPInput(),
	// 	)
	// }

	resourceMap["AWS::ECS::TaskDefinition"] = func() chain.Chain {
		return chain.NewChain(
			noseyparker.NewConvertToNPInput(),
		)
	}

	resourceMap["AWS::SSM::Document"] = func() chain.Chain {
		return chain.NewChain(
			noseyparker.NewConvertToNPInput(),
		)
	}

	// resourceMap["AWS::SSM::Parameter"] = func() chain.Chain {
	// 	return chain.NewChain(
	// 		ssm.NewAWSListSSMParameters(),
	// 		noseyparker.NewConvertToNPInput(),
	// 	)
	// }

	resourceMap["AWS::StepFunctions::StateMachine"] = func() chain.Chain {
		return chain.NewChain(
			stepfunctions.NewAWSListExecutions(),
			stepfunctions.NewAWSGetExecutionDetails(),
			noseyparker.NewConvertToNPInput(),
		)
	}

	return resourceMap
}

func (fs *AWSFindSecrets) Process(resource *types.EnrichedResourceDescription) error {
	constructor, ok := fs.resourceMap[resource.TypeName]
	if !ok {
		slog.Error("Unsupported resource type", "resource", resource)
		return nil
	}

	slog.Debug("Dispatching resource for processing", "resource_type", resource.TypeName, "resource_id", resource.Identifier)

	// Create pair and send to processor
	args := fs.Args()
	if maxEvents, ok := args["max-events"]; ok {
		message.Info("AWSFindSecrets passing max-events in ResourceChainPair",
			"resource_type", resource.TypeName,
			"max_events_value", maxEvents,
			"max_events_type", fmt.Sprintf("%T", maxEvents))
	} else {
		message.Info("AWSFindSecrets did not find max-events in Args()",
			"resource_type", resource.TypeName,
			"available_keys", func() []string {
				keys := make([]string, 0, len(args))
				for k := range args {
					keys = append(keys, k)
				}
				return keys
			}())
	}

	pair := &ResourceChainPair{
		Resource:         resource,
		ChainConstructor: constructor,
		Args:             args,
	}

	return fs.Send(pair)
}

func (fs *AWSFindSecrets) Complete() error {
	// No manual coordination needed - framework handles it
	return nil
}

func (fs *AWSFindSecrets) Permissions() []cfg.Permission {
	return []cfg.Permission{
		{
			Platform:   "aws",
			Permission: "cloudcontrol:ListResources",
		},
		{
			Platform:   "aws",
			Permission: "cloudformation:ListStacks",
		},
		{
			Platform:   "aws",
			Permission: "ec2:DescribeInstanceAttribute",
		},
		{
			Platform:   "aws",
			Permission: "ec2:DescribeInstances",
		},
		{
			Platform:   "aws",
			Permission: "ecs:ListTaskDefinitions",
		},
		{
			Platform:   "aws",
			Permission: "kms:Decrypt",
		},
		{
			Platform:   "aws",
			Permission: "lambda:GetFunction",
		},
		{
			Platform:   "aws",
			Permission: "lambda:ListFunctions",
		},
		{
			Platform:   "aws",
			Permission: "logs:FilterLogEvents",
		},
		{
			Platform:   "aws",
			Permission: "logs:DescribeLogStreams",
		},
		{
			Platform:   "aws",
			Permission: "logs:DescribeMetricFilters",
		},
		{
			Platform:   "aws",
			Permission: "logs:DescribeSubscriptionFilters",
		},
		{
			Platform:   "aws",
			Permission: "logs:DescribeDestinations",
		},
		{
			Platform:   "aws",
			Permission: "ssm:ListDocuments",
		},
		{
			Platform:   "aws",
			Permission: "states:ListStateMachines",
		},
		{
			Platform:   "aws",
			Permission: "sts:GetCallerIdentity",
		},
	}
}
