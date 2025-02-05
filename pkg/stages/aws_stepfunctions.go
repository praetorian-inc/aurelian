package stages

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AwsStepFunctionsListExecutionsStage gets the list of Step Functions executions
func AwsStepFunctionsListExecutionsStage(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan sfntypes.ExecutionListItem {
	logger := logs.NewStageLogger(ctx, opts, "AwsStepFunctionsGetExecutionsStage")
	out := make(chan sfntypes.ExecutionListItem)

	logger.Info("Getting Step Functions executions")

	var nextToken *string
	go func() {
		defer close(out)
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}

			for {
				sfnClient := sfn.NewFromConfig(config)

				output, err := sfnClient.ListExecutions(ctx, &sfn.ListExecutionsInput{
					StateMachineArn: aws.String(resource.Identifier),
					MaxResults:      1000,
					NextToken:       nextToken,
				})
				if err != nil {
					logger.Error("Could not get Step Functions executions, error: " + err.Error())
					continue
				}

				for _, execution := range output.Executions {
					out <- execution
				}

				if output.NextToken == nil {
					break
				}
			}
		}
	}()

	logger.Info("Completed getting Step Functions executions")
	return out
}

// AwsStepFunctionsGetExecutionDetailsStage gets the details of a Step Functions execution
func AwsStepFunctionsGetExecutionDetailsStage(ctx context.Context, opts []*types.Option, in <-chan sfntypes.ExecutionListItem) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "AwsStepFunctionsGetExecutionDetailsStage")
	out := make(chan types.EnrichedResourceDescription)

	logger.Info("Getting Step Functions execution details")

	go func() {
		defer close(out)
		for resource := range in {
			// get region from ARN
			parsed, err := arn.Parse(*resource.StateMachineArn)
			if err != nil {
				logger.Error("Could not parse Step Functions ARN, error: " + err.Error())
				continue
			}

			config, err := helpers.GetAWSCfg(parsed.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}

			sfnClient := sfn.NewFromConfig(config)

			logger.Debug("Getting Step Functions execution details", slog.String("execution_arn", *resource.ExecutionArn))
			details, err := sfnClient.DescribeExecution(ctx, &sfn.DescribeExecutionInput{
				ExecutionArn: resource.ExecutionArn,
			})
			if err != nil {
				logger.Error("Could not get Step Functions execution details, error: " + err.Error())
				continue
			}

			encodedExec, err := json.Marshal(details)
			if err != nil {
				logger.Error("Could not marshal Step Functions execution details, error: " + err.Error())
				continue
			}

			out <- types.EnrichedResourceDescription{
				Identifier: *resource.ExecutionArn,
				TypeName:   "AWS::StepFunctions::Execution::Details",
				Region:     parsed.Region,
				AccountId:  parsed.AccountID,
				Properties: string(encodedExec),
				Arn:        parsed,
			}
		}
	}()

	logger.Info("Completed getting Step Functions execution details")
	return out
}

// AwsStateMachineExecutionDetailsToNpInputStage converts the AWS Step Functions execution
// details to Nosey Parker input format and preserves the execution ID and state machine ARN
func AwsStateMachineExecutionDetailsToNpInputStage(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.NpInput {
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for data := range in {

			out <- types.NpInput{
				ContentBase64: base64.StdEncoding.EncodeToString([]byte(data.Properties.(string))),
				Provenance: types.NpProvenance{
					Platform:     "aws",
					ResourceType: data.TypeName,
					ResourceID:   data.Identifier, // this identifier has the execution id + statemachine arn
					Region:       data.Region,
					AccountID:    data.AccountId,
				},
			}
		}
	}()

	return out
}
