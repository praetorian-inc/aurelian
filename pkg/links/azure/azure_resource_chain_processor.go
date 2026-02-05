package azure

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AzureResourceChainProcessor processes AzureResourceChainPair objects concurrently
type AzureResourceChainProcessor struct {
	name    string
	args    map[string]any
	outputs []any
}

// ProcessablePlugin represents a plugin that can process input
type ProcessablePlugin interface {
	Process(ctx context.Context, input any) ([]any, error)
}

type AzureResourceChainPair struct {
	Resource      *output.CloudResource
	PluginFactory func(map[string]any) ProcessablePlugin
	Args          map[string]any
}

func NewAzureResourceChainProcessor(args map[string]any) *AzureResourceChainProcessor {
	return &AzureResourceChainProcessor{
		name:    "azure-resource-chain-processor",
		args:    args,
		outputs: make([]any, 0),
	}
}

func (p *AzureResourceChainProcessor) Process(ctx context.Context, input any) ([]any, error) {
	pair, ok := input.(*AzureResourceChainPair)
	if !ok {
		return nil, fmt.Errorf("expected *AzureResourceChainPair, got %T", input)
	}

	slog.Debug("Processing Azure resource chain",
		"resource_type", pair.Resource.ResourceType,
		"resource_id", pair.Resource.ResourceID)

	// Build the specific plugin for this resource type
	essentialArgs := p.extractEssentialArgs(pair.Args)
	resourcePlugin := pair.PluginFactory(essentialArgs)

	// Process the resource
	outputs, err := resourcePlugin.Process(ctx, pair.Resource)
	if err != nil {
		slog.Error("Error processing Azure resource chain", "resource", pair.Resource, "error", err)
		return nil, err
	}

	// Collect outputs
	for _, output := range outputs {
		if npInput, ok := output.(types.NpInput); ok {
			slog.Debug("Forwarding output", "resource_type", pair.Resource.ResourceType, "output_type", fmt.Sprintf("%T", npInput))
			p.outputs = append(p.outputs, npInput)
		}
	}

	slog.Debug("Completed processing Azure resource chain", "resource_type", pair.Resource.ResourceType)
	return p.outputs, nil
}

// extractEssentialArgs extracts only Azure-specific parameters needed by resource chains
// Excludes module-level and outputter-specific parameters to prevent conflicts
func (p *AzureResourceChainProcessor) extractEssentialArgs(args map[string]any) map[string]any {
	// Only include essential Azure parameters that resource chains need
	essentialParams := map[string]bool{
		"cache-dir":        true, // Cache directory
		"cache-ttl":        true, // Cache TTL
		"disable-cache":    true, // Cache disable flag
		"cache-ext":        true, // Cache extension
		"cache-error-resp": true, // Cache error response flag
		"worker-count":     true, // Worker count for Azure operations
	}

	essential := make(map[string]any)
	for key, value := range args {
		if essentialParams[key] {
			essential[key] = value
		} else {
			slog.Debug("Excluding non-essential parameter from Azure resource chain", "param", key)
		}
	}

	return essential
}

func (p *AzureResourceChainProcessor) Outputs() []any {
	return p.outputs
}
