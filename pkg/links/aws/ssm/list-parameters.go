package ssm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSListSSMParameters struct {
	*base.NativeAWSLink
}

func NewAWSListSSMParameters(args map[string]any) *AWSListSSMParameters {
	return &AWSListSSMParameters{
		NativeAWSLink: base.NewNativeAWSLink("ssm-list-parameters", args),
	}
}

func (a *AWSListSSMParameters) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}

	config, err := a.GetConfig(ctx, resource.Region)
	if err != nil {
		return nil, err
	}

	ssmClient := ssm.NewFromConfig(config)
	describeInput := &ssm.DescribeParametersInput{}

	results := []types.EnrichedResourceDescription{}
	for {
		result, err := ssmClient.DescribeParameters(ctx, describeInput)
		if err != nil {
			slog.Debug("Failed to list SSM parameters: " + err.Error())
			break
		}

		for _, param := range result.Parameters {
			erd, err := a.parseParameter(ctx, ssmClient, param, resource)
			if err != nil {
				slog.Debug("Failed to parse parameter: " + err.Error())
				continue
			}

			results = append(results, erd)
		}

		if result.NextToken == nil {
			break
		}
		describeInput.NextToken = result.NextToken
	}

	outputs := make([]any, len(results))
	for i, erd := range results {
		outputs[i] = erd
	}

	return outputs, nil
}

func (a *AWSListSSMParameters) parseParameter(ctx context.Context, ssmClient *ssm.Client, param ssmtypes.ParameterMetadata, resource *types.EnrichedResourceDescription) (types.EnrichedResourceDescription, error) {
	paramInput := &ssm.GetParameterInput{
		Name:           param.Name,
		WithDecryption: aws.Bool(true),
	}

	paramOutput, err := ssmClient.GetParameter(ctx, paramInput)
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
