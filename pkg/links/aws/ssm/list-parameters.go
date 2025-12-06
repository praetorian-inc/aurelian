package ssm

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSListSSMParameters struct {
	*base.AwsReconLink
}

func NewAWSListSSMParameters(configs ...cfg.Config) chain.Link {
	ssm := &AWSListSSMParameters{}
	ssm.AwsReconLink = base.NewAwsReconLink(ssm, configs...)
	return ssm
}

func (a *AWSListSSMParameters) Process(resource *types.EnrichedResourceDescription) error {
	config, err := a.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		return err
	}

	ssmClient := ssm.NewFromConfig(config)
	input := &ssm.DescribeParametersInput{}

	results := []types.EnrichedResourceDescription{}
	for {
		result, err := ssmClient.DescribeParameters(a.Context(), input)
		if err != nil {
			slog.Debug("Failed to list SSM parameters: " + err.Error())
			break
		}

		for _, param := range result.Parameters {
			erd, err := a.parseParameter(ssmClient, param, resource)
			if err != nil {
				slog.Debug("Failed to parse parameter: " + err.Error())
				continue
			}

			results = append(results, erd)
		}

		if result.NextToken == nil {
			break
		}
		input.NextToken = result.NextToken
	}

	for _, erd := range results {
		a.Send(erd)
	}

	return nil
}

func (a *AWSListSSMParameters) parseParameter(ssmClient *ssm.Client, param ssmtypes.ParameterMetadata, resource *types.EnrichedResourceDescription) (types.EnrichedResourceDescription, error) {
	paramInput := &ssm.GetParameterInput{
		Name:           param.Name,
		WithDecryption: aws.Bool(true),
	}

	paramOutput, err := ssmClient.GetParameter(a.Context(), paramInput)
	if err != nil {
		return types.EnrichedResourceDescription{}, fmt.Errorf("failed to get parameter %s: %w", *param.Name, err)
	}

	properties, err := json.Marshal(map[string]interface{}{
		"Name":             param.Name,
		"Type":             param.Type,
		"Value":            paramOutput.Parameter.Value,
		"Description":      param.Description,
		"LastModifiedDate": param.LastModifiedDate,
		"Version":          param.Version,
	})

	if err != nil {
		return types.EnrichedResourceDescription{}, fmt.Errorf("failed to marshal parameter properties: %w", err)
	}

	erd := types.EnrichedResourceDescription{
		Identifier: *param.Name,
		TypeName:   resource.TypeName,
		Region:     resource.Region,
		Properties: string(properties),
		AccountId:  resource.AccountId,
	}

	erd.Arn = erd.ToArn()

	return erd, nil
}
