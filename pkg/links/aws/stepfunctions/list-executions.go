package stepfunctions

import (
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSListExecutions struct {
	*base.AwsReconLink
}

func NewAWSListExecutions(configs ...cfg.Config) chain.Link {
	le := &AWSListExecutions{}
	le.AwsReconLink = base.NewAwsReconLink(le, configs...)
	return le
}

func (le *AWSListExecutions) Process(resource *types.EnrichedResourceDescription) error {
	config, err := le.GetConfig(resource.Region, options.JanusParamAdapter(le.Params()))
	if err != nil {
		slog.Debug("Failed to get AWS config for region", "region", resource.Region, "error", err)
		return err
	}

	var nextToken *string
	executions := []sfntypes.ExecutionListItem{}
	for {
		sfnClient := sfn.NewFromConfig(config)

		output, err := sfnClient.ListExecutions(le.Context(), &sfn.ListExecutionsInput{
			StateMachineArn: aws.String(resource.Identifier),
			MaxResults:      1000,
			NextToken:       nextToken,
		})

		if err != nil {
			slog.Debug("Could not get Step Functions executions, error: " + err.Error())
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

	return nil
}
