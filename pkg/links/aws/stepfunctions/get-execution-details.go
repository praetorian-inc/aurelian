package stepfunctions

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSGetExecutionDetails struct {
	*base.NativeAWSLink
}

func NewAWSGetExecutionDetails(args map[string]any) *AWSGetExecutionDetails {
	return &AWSGetExecutionDetails{
		NativeAWSLink: base.NewNativeAWSLink("get-execution-details", args),
	}
}

func (ged *AWSGetExecutionDetails) Process(ctx context.Context, input any) ([]any, error) {
	execution, ok := input.(*sfntypes.ExecutionListItem)
	if !ok {
		return nil, fmt.Errorf("expected *sfntypes.ExecutionListItem, got %T", input)
	}

	parsed, err := arn.Parse(*execution.StateMachineArn)
	if err != nil {
		slog.Debug("Could not parse Step Functions ARN", "error", err)
		return nil, nil
	}

	config, err := ged.GetConfig(ctx, parsed.Region)
	if err != nil {
		slog.Debug("Could not get AWS config", "region", parsed.Region, "error", err)
		return nil, nil
	}

	sfnClient := sfn.NewFromConfig(config)

	details, err := sfnClient.DescribeExecution(ctx, &sfn.DescribeExecutionInput{
		ExecutionArn: execution.ExecutionArn,
	})

	if err != nil {
		slog.Debug("Could not get Step Functions execution details", "error", err)
		return nil, nil
	}

	encodedExec, err := json.Marshal(details)
	if err != nil {
		slog.Debug("Could not marshal Step Functions execution details", "error", err)
		return nil, nil
	}

	ged.Send(types.EnrichedResourceDescription{
		Identifier: *execution.ExecutionArn,
		TypeName:   "AWS::StepFunctions::Execution::Details",
		Region:     parsed.Region,
		AccountId:  parsed.AccountID,
		Properties: string(encodedExec),
		Arn:        parsed,
	})

	return ged.Outputs(), nil
}
