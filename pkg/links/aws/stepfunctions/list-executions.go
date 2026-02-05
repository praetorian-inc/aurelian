package stepfunctions

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSListExecutions struct {
	*base.NativeAWSLink
}

func NewAWSListExecutions(args map[string]any) *AWSListExecutions {
	return &AWSListExecutions{
		NativeAWSLink: base.NewNativeAWSLink("list-executions", args),
	}
}

func (le *AWSListExecutions) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}

	config, err := le.GetConfig(ctx, resource.Region)
	if err != nil {
		slog.Debug("Failed to get AWS config for region", "region", resource.Region, "error", err)
		return nil, fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	var nextToken *string
	executions := []sfntypes.ExecutionListItem{}
	for {
		sfnClient := sfn.NewFromConfig(config)

		output, err := sfnClient.ListExecutions(ctx, &sfn.ListExecutionsInput{
			StateMachineArn: aws.String(resource.Identifier),
			MaxResults:      1000,
			NextToken:       nextToken,
		})

		if err != nil {
			slog.Debug("Could not get Step Functions executions", "error", err)
			continue
		}

		executions = append(executions, output.Executions...)

		if output.NextToken == nil {
			break
		}

		nextToken = output.NextToken
	}

	for _, execution := range executions {
		le.Send(execution)
	}

	return le.Outputs(), nil
}
