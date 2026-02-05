package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSLambdaFunctionURL struct {
	*base.NativeAWSLink
}

func NewAWSLambdaFunctionURL(args map[string]any) *AWSLambdaFunctionURL {
	return &AWSLambdaFunctionURL{
		NativeAWSLink: base.NewNativeAWSLink("lambda-function-url", args),
	}
}

func (l *AWSLambdaFunctionURL) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}
	if resource.TypeName != "AWS::Lambda::Function" {
		slog.Debug("Skipping non-Lambda function", "resource", resource.TypeName)
		return l.Outputs(), nil
	}

	functionURL, err := l.getFunctionURL(ctx, resource)
	if err != nil {
		slog.Debug("No function URL configured or error retrieving URL", "resource", resource.Identifier, "error", err)
		return l.Outputs(), nil
	}

	if functionURL == "" {
		return l.Outputs(), nil
	}

	// Add the function URL to the resource properties
	updatedERD, err := l.addFunctionURLToProperties(resource, functionURL)
	if err != nil {
		slog.Error("Failed to add function URL to properties", "error", err)
		l.Send(resource)
		return l.Outputs(), nil
	}

	l.Send(updatedERD)
	return l.Outputs(), nil
}

func (l *AWSLambdaFunctionURL) getFunctionURL(ctx context.Context, resource *types.EnrichedResourceDescription) (string, error) {
	config, err := l.GetConfig(ctx, resource.Region)
	if err != nil {
		return "", fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	lambdaClient := lambda.NewFromConfig(config)

	input := &lambda.GetFunctionUrlConfigInput{
		FunctionName: aws.String(resource.Identifier),
	}

	output, err := lambdaClient.GetFunctionUrlConfig(ctx, input)
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