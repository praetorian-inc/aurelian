package enrichers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::Lambda::Function", fetchFunctionURLsWrapper)
}

type LambdaClient interface {
	GetFunctionUrlConfig(ctx context.Context, input *lambda.GetFunctionUrlConfigInput, opts ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error)
}

func fetchFunctionURLsWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	client := lambda.NewFromConfig(cfg.AWSConfig)
	return FetchFunctionURLs(cfg, r, client)
}

func FetchFunctionURLs(cfg plugin.EnricherConfig, r *output.AWSResource, client LambdaClient) error {
	out, err := client.GetFunctionUrlConfig(cfg.Context, &lambda.GetFunctionUrlConfigInput{
		FunctionName: &r.ResourceID,
	})
	if err != nil {
		var notFound *lambdatypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil
		}
		slog.Warn("lambda enricher: unexpected error",
			"resource_id", r.ResourceID,
			"error", err,
			"error_type", fmt.Sprintf("%T", err),
		)
		return fmt.Errorf("failed to get function URL config: %w", err)
	}

	if out.FunctionUrl != nil {
		r.Properties["FunctionUrl"] = *out.FunctionUrl
	}
	if out.AuthType != "" {
		r.Properties["FunctionUrlAuthType"] = string(out.AuthType)
	}

	return nil
}

func propertyKeys(props map[string]any) []string {
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	return keys
}
