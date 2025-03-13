package stepfunctions

import (
	"encoding/json"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSGetExecutionDetails struct {
	*base.AwsReconLink
}

func NewAWSGetExecutionDetails(configs ...cfg.Config) chain.Link {
	ged := &AWSGetExecutionDetails{}
	ged.AwsReconLink = base.NewAwsReconLink(ged, configs...)
	return ged
}

func (ged *AWSGetExecutionDetails) Process(execution *sfntypes.ExecutionListItem) error {
	parsed, err := arn.Parse(*execution.StateMachineArn)
	if err != nil {
		slog.Debug("Could not parse Step Functions ARN, error: " + err.Error())
		return nil
	}

	config, err := ged.GetConfig(parsed.Region, options.JanusParamAdapter(ged.Params()))
	if err != nil {
		slog.Debug("Could not get AWS config, error: " + err.Error())
		return nil
	}

	sfnClient := sfn.NewFromConfig(config)

	details, err := sfnClient.DescribeExecution(ged.Context(), &sfn.DescribeExecutionInput{
		ExecutionArn: execution.ExecutionArn,
	})

	if err != nil {
		slog.Debug("Could not get Step Functions execution details, error: " + err.Error())
		return nil
	}

	encodedExec, err := json.Marshal(details)
	if err != nil {
		slog.Debug("Could not marshal Step Functions execution details, error: " + err.Error())
		return nil
	}

	return ged.Send(types.EnrichedResourceDescription{
		Identifier: *execution.ExecutionArn,
		TypeName:   "AWS::StepFunctions::Execution::Details",
		Region:     parsed.Region,
		AccountId:  parsed.AccountID,
		Properties: string(encodedExec),
		Arn:        parsed,
	})
}
