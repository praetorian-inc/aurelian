package enrichers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::Lambda::Function", fetchFunctionURLsWrapper)
	plugin.RegisterEnricher("AWS::Lambda::Function", fetchFunctionImageWrapper)
}

type LambdaClient interface {
	GetFunctionUrlConfig(ctx context.Context, input *lambda.GetFunctionUrlConfigInput, opts ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error)
}

// LambdaCodeClient is the one call that can return a function's image
// reference. It is separate from LambdaClient so the URL enricher's mocks do
// not have to grow a method they never exercise.
type LambdaCodeClient interface {
	GetFunction(ctx context.Context, input *lambda.GetFunctionInput, opts ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error)
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

// FetchFunctionImage fills Code.ImageUri for image-packaged functions.
//
// Three facts force this shape:
//
//  1. `Code/ImageUri` is a *write-only* property in the AWS::Lambda::Function
//     CloudFormation schema, so CloudControl GetResource never returns it. No
//     amount of hydrateIfMissing can produce an image reference — this call is
//     the only way to get one.
//  2. ListFunctions already returns PackageType for free, so the call is made
//     only for the image-packaged minority. A zip-packaged function — the
//     default and the common case — costs nothing.
//  3. GetFunctionConfiguration does not return Code at all; it has to be
//     GetFunction.
//
// Absent PackageType means "don't know", and the conservative reading is to
// make no call: the hot paths (list-all, public-resources) must not pay a
// per-resource API call for version data.
func FetchFunctionImage(cfg plugin.EnricherConfig, r *output.AWSResource, client LambdaCodeClient) error {
	pt, _ := r.Properties["PackageType"].(string)
	if !strings.EqualFold(pt, "Image") {
		return nil
	}
	if codeImageURIPresent(r.Properties) {
		return nil
	}

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	out, err := client.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: &r.ResourceID})
	if err != nil {
		var notFound *lambdatypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil
		}
		// Best-effort, like every other enrichment: a function whose code
		// cannot be read simply contributes no image technology.
		slog.Warn("lambda image enricher: GetFunction failed",
			"resource_id", r.ResourceID, "error", err)
		return nil
	}
	if out.Code == nil {
		return nil
	}

	// Copy by name, never the whole Code struct. Code.Location is a presigned,
	// credential-bearing S3 URL; it must not reach the property bag, which is
	// serialised into output and shipped to guard.
	code := map[string]any{}
	if v := aws.ToString(out.Code.ImageUri); v != "" {
		code["ImageUri"] = v
	}
	if v := aws.ToString(out.Code.ResolvedImageUri); v != "" {
		code["ResolvedImageUri"] = v
	}
	if len(code) == 0 {
		return nil
	}

	if r.Properties == nil {
		r.Properties = map[string]any{}
	}
	existing, ok := r.Properties["Code"].(map[string]any)
	if !ok {
		r.Properties["Code"] = code
		return nil
	}
	for k, v := range code {
		if _, present := existing[k]; !present {
			existing[k] = v
		}
	}
	return nil
}

func fetchFunctionImageWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	return FetchFunctionImage(cfg, r, lambda.NewFromConfig(cfg.AWSConfig))
}

func codeImageURIPresent(props map[string]any) bool {
	code, ok := props["Code"].(map[string]any)
	if !ok {
		return false
	}
	uri, ok := code["ImageUri"].(string)
	return ok && uri != ""
}
