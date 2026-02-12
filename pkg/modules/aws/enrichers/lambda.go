package enrichers

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	// Register enricher for Lambda functions
	plugin.RegisterEnricher("AWS::Lambda::Function", fetchFunctionURLsWrapper)
}

// LambdaClient interface for testing
type LambdaClient interface {
	GetFunctionUrlConfig(ctx context.Context, input *lambda.GetFunctionUrlConfigInput, opts ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error)
}

// fetchFunctionURLsWrapper adapts the enricher signature for registration
func fetchFunctionURLsWrapper(cfg plugin.EnricherConfig, r *output.CloudResource) error {
	client := lambda.NewFromConfig(cfg.AWSConfig)
	return FetchFunctionURLs(cfg, r, client)
}

// FetchFunctionURLs enriches a Lambda function with its function URL configuration.
// Returns nil if the function has no URL (not an error).
func FetchFunctionURLs(cfg plugin.EnricherConfig, r *output.CloudResource, client LambdaClient) error {
	out, err := client.GetFunctionUrlConfig(cfg.Context, &lambda.GetFunctionUrlConfigInput{
		FunctionName: &r.ResourceID,
	})
	if err != nil {
		// ResourceNotFoundException means no function URL configured - not an error
		var notFound *lambdatypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("failed to get function URL config: %w", err)
	}

	// Add function URL properties
	if out.FunctionUrl != nil {
		r.Properties["FunctionUrl"] = *out.FunctionUrl
	}
	if out.AuthType != "" {
		r.Properties["FunctionUrlAuthType"] = string(out.AuthType)
	}

	return nil
}
