package lambda

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSLambdaFunctionURL struct {
	*base.AwsReconLink
}

func NewAWSLambdaFunctionURL(configs ...cfg.Config) chain.Link {
	l := &AWSLambdaFunctionURL{}
	l.AwsReconLink = base.NewAwsReconLink(l, configs...)
	return l
}

func (l *AWSLambdaFunctionURL) Process(resource *types.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::Lambda::Function" {
		slog.Debug("Skipping non-Lambda function", "resource", resource.TypeName)
		return nil
	}

	functionURL, err := l.getFunctionURL(resource)
	if err != nil {
		slog.Debug("No function URL configured or error retrieving URL", "resource", resource.Identifier, "error", err)
		return nil
	}

	if functionURL == "" {
		return nil
	}

	// Add the function URL to the resource properties
	updatedERD, err := l.addFunctionURLToProperties(resource, functionURL)
	if err != nil {
		slog.Error("Failed to add function URL to properties", "error", err)
		return l.Send(resource)
	}

	return l.Send(updatedERD)
}

func (l *AWSLambdaFunctionURL) getFunctionURL(resource *types.EnrichedResourceDescription) (string, error) {
	config, err := l.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		return "", fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	lambdaClient := lambda.NewFromConfig(config)

	input := &lambda.GetFunctionUrlConfigInput{
		FunctionName: aws.String(resource.Identifier),
	}

	output, err := lambdaClient.GetFunctionUrlConfig(l.Context(), input)
	if err != nil {
		return "", fmt.Errorf("failed to get function URL config for %s: %w", resource.Identifier, err)
	}

	if output.FunctionUrl == nil {
		return "", nil
	}

	return *output.FunctionUrl, nil
}

func (l *AWSLambdaFunctionURL) addFunctionURLToProperties(resource *types.EnrichedResourceDescription, functionURL string) (*types.EnrichedResourceDescription, error) {
	var propsMap map[string]any

	if resource.Properties == nil {
		propsMap = make(map[string]any)
	} else {
		propsStr, ok := resource.Properties.(string)
		if !ok {
			propsBytes, err := json.Marshal(resource.Properties)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal properties: %w", err)
			}
			propsStr = string(propsBytes)
		}

		// Handle double-escaped JSON strings
		if len(propsStr) > 0 && propsStr[0] == '"' {
			var unescaped string
			if err := json.Unmarshal([]byte(propsStr), &unescaped); err != nil {
				return nil, fmt.Errorf("failed to unescape properties: %w", err)
			}
			propsStr = unescaped
		}

		if err := json.Unmarshal([]byte(propsStr), &propsMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal properties: %w", err)
		}
	}

	// Add the function URL to properties
	propsMap["FunctionUrl"] = functionURL

	// Marshal back to JSON string
	updatedPropsBytes, err := json.Marshal(propsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated properties: %w", err)
	}

	// Create a copy of the original ERD with updated properties
	updatedERD := *resource
	updatedERD.Properties = string(updatedPropsBytes)

	return &updatedERD, nil
}