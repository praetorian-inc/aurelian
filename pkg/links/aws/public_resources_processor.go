package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
)

// AWSPublicResourcesProcessor processes ResourceChainPair objects concurrently for public resources
type AWSPublicResourcesProcessor struct {
	*base.NativeAWSLink
}

func NewAWSPublicResourcesProcessor(args map[string]any) *AWSPublicResourcesProcessor {
	return &AWSPublicResourcesProcessor{
		NativeAWSLink: base.NewNativeAWSLink("aws-public-resources-processor", args),
	}
}

func (p *AWSPublicResourcesProcessor) Process(ctx context.Context, input any) ([]any, error) {
	pair, ok := input.(*ResourceChainPair)
	if !ok {
		return nil, fmt.Errorf("expected *ResourceChainPair, got %T", input)
	}

	slog.Debug("Processing public resource chain",
		"resource_type", pair.Resource.TypeName,
		"resource_id", pair.Resource.Identifier)

	// Extract essential AWS parameters
	essentialArgs := p.extractEssentialArgs(pair.Args)

	// Process the resource using the constructor function
	// In native architecture, we directly call Process methods
	processor := AwsPublicResources{
		NativeAWSLink: base.NewNativeAWSLink("temp-processor", essentialArgs),
		processedS3:   make(map[string]bool),
	}

	outputs, err := processor.Process(ctx, pair.Resource)
	if err != nil {
		slog.Error("Error processing public resource chain", "resource", pair.Resource, "error", err)
		return nil, err
	}

	slog.Debug("Completed processing public resource chain", "resource_type", pair.Resource.TypeName)
	return outputs, nil
}

// extractEssentialArgs extracts only AWS-specific parameters needed by resource chains
// Excludes module-level and outputter-specific parameters to prevent conflicts
func (p *AWSPublicResourcesProcessor) extractEssentialArgs(args map[string]any) map[string]any {
	// Only include essential AWS parameters that resource chains need
	essentialParams := map[string]bool{
		"profile":          true, // AWS profile
		"regions":          true, // AWS regions
		"cache-dir":        true, // Cache directory
		"cache-ttl":        true, // Cache TTL
		"disable-cache":    true, // Cache disable flag
		"cache-ext":        true, // Cache extension
		"cache-error-resp": true, // Cache error response flag
	}

	essential := make(map[string]any)
	for key, value := range args {
		if essentialParams[key] {
			essential[key] = value
		} else {
			slog.Debug("Excluding non-essential parameter from public resource chain", "param", key)
		}
	}

	return essential
}