package stages

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	awstypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func AwsStepFunctionsExecutionsToNpInputStage(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.NpInput {
	out := make(chan types.NpInput)

	logger := logs.NewStageLogger(ctx, opts, "AwsStepFunctionsExecutionsToNpInputStage")

	go func() {
		defer close(out)
		for resource := range in {
			for execution := range AwsStepFunctionsGetExecutionsStage(ctx, opts, Generator([]types.EnrichedResourceDescription{resource})) {
				logger.Info("Writing to stdin pipe: " + execution)
				encodedExecution := base64.StdEncoding.EncodeToString([]byte(execution))
				out <- types.NpInput{
					ContentBase64: encodedExecution,
					Provenance: types.NpProvenance{
						Platform:     "aws",
						ResourceType: "AWS::StepFunctions::Execution",
						ResourceID:   resource.Identifier,
						Region:       resource.Region,
						AccountID:    resource.AccountId,
					},
				}
			}
		}
	}()

	return out
}

func AwsStepFunctionsGetExecutionsStage(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "AwsStepFunctionsGetExecutionsStage")
	out := make(chan string)

	logger.Info("Getting Step Functions executions")

	go func() {
		defer close(out)
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}

			var executions []awstypes.ExecutionListItem

			output, err := fetchStepFunctionExecutions(ctx, logger, config, resource.Identifier, nil)
			if err != nil {
				logger.Error("Could not get Step Functions executions, error: " + err.Error())
				continue
			}
			executions = output.Executions

			for output.NextToken != nil {
				logger.Info("Getting more Step Functions executions in region " + resource.Region)
				output, err = fetchStepFunctionExecutions(ctx, logger, config, resource.Identifier, output.NextToken)
				if err != nil {
					logger.Error("Could not get Step Functions executions, error: " + err.Error())
					continue
				}
				executions = append(executions, output.Executions...)
			}

			logger.Info("Found " + strconv.Itoa(len(executions)) + " Step Functions executions")
			for _, execution := range executions {
				encodedExecution, err := json.Marshal(execution)
				logger.Info("Encoding execution: " + string(encodedExecution))
				if err != nil {
					logger.Error("Could not marshal Step Functions execution, error: " + err.Error())
					continue
				}
				logger.Info("Writing execution: " + string(encodedExecution))
				out <- string(encodedExecution)
			}
		}
	}()

	logger.Info("Completed getting Step Functions executions")
	return out
}

func fetchStepFunctionExecutions(ctx context.Context, logger *slog.Logger, config aws.Config, stateMachineArn string, nextToken *string) (*sfn.ListExecutionsOutput, error) {
	sfnClient := sfn.NewFromConfig(config)

	output, err := sfnClient.ListExecutions(ctx, &sfn.ListExecutionsInput{
		StateMachineArn: aws.String(stateMachineArn),
		MaxResults:      1000,
		NextToken:       nextToken,
	})
	if err != nil {
		logger.Error("Could not get Step Functions executions, error: " + err.Error())
		return nil, err
	}

	return output, nil
}
