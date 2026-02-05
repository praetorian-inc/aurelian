package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AWSResourceChainProcessor processes ResourceChainPair objects concurrently
type AWSResourceChainProcessor struct {
	*base.NativeAWSLink
}

type ResourceChainPair struct {
	Resource         *types.EnrichedResourceDescription
	ChainConstructor func() []any // Returns processing chain functions
	Args             map[string]any
}

func NewAWSResourceChainProcessor(args map[string]any) *AWSResourceChainProcessor {
	return &AWSResourceChainProcessor{
		NativeAWSLink: base.NewNativeAWSLink("aws-resource-chain-processor", args),
	}
}

func (p *AWSResourceChainProcessor) Process(ctx context.Context, input any) ([]any, error) {
	pair, ok := input.(*ResourceChainPair)
	if !ok {
		return nil, fmt.Errorf("expected *ResourceChainPair, got %T", input)
	}

	slog.Debug("Processing resource chain",
		"resource_type", pair.Resource.TypeName,
		"resource_id", pair.Resource.Identifier)

	// Extract essential AWS parameters
	essentialArgs := p.extractEssentialArgs(pair.Args)

	// Process the resource using find_secrets processor
	processor := AWSFindSecrets{
		NativeAWSLink: base.NewNativeAWSLink("temp-processor", essentialArgs),
	}

	outputs, err := processor.Process(ctx, pair.Resource)
	if err != nil {
		slog.Error("Error processing resource chain", "resource", pair.Resource, "error", err)
		return nil, err
	}

	slog.Debug("Completed processing resource chain", "resource_type", pair.Resource.TypeName)
	return outputs, nil
}

// extractEssentialArgs extracts only AWS-specific parameters needed by resource chains
// Excludes module-level and outputter-specific parameters to prevent conflicts
func (p *AWSResourceChainProcessor) extractEssentialArgs(args map[string]any) map[string]any {
	// Only include essential AWS parameters that resource chains need
	essentialParams := map[string]bool{
		"profile":          true, // AWS profile
		"profile-dir":      true, // AWS profile directory
		"regions":          true, // AWS regions
		"cache-dir":        true, // Cache directory
		"cache-ttl":        true, // Cache TTL
		"disable-cache":    true, // Cache disable flag
		"cache-ext":        true, // Cache extension
		"cache-error-resp": true, // Cache error response flag
		"max-events":       true, // Max log events for CloudWatch Logs resources
		"max-streams":      true, // Max log streams for CloudWatch Logs resources
		"newest-first":     true, // Fetch newest events first for CloudWatch Logs resources
	}

	essential := make(map[string]any)
	for key, value := range args {
		if essentialParams[key] {
			essential[key] = value
		} else {
			slog.Debug("Excluding non-essential parameter from resource chain", "param", key)
		}
	}

	return essential
}
