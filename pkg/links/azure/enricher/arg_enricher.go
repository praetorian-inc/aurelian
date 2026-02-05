package enricher

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// ARGEnrichmentLink enriches Azure resources with additional security testing commands
type ARGEnrichmentLink struct {
	*base.NativeAzureLink
	registry *EnrichmentRegistry
}

// NewARGEnrichmentLink creates a new enrichment link with all available enrichers
func NewARGEnrichmentLink(args map[string]any) *ARGEnrichmentLink {
	return &ARGEnrichmentLink{
		NativeAzureLink: base.NewNativeAzureLink("arg-enrichment", args),
		registry:        NewEnrichmentRegistry(),
	}
}

// Parameters returns the parameters required by this link
func (l *ARGEnrichmentLink) Parameters() []plugin.Parameter {
	params := base.StandardAzureParams()
	params = append(params, plugin.NewParam[bool]("disable-enrichment", "Disable resource enrichment"))
	return params
}

// Process enriches Azure resources with security testing commands based on template ID
func (l *ARGEnrichmentLink) Process(ctx context.Context, input any) ([]any, error) {
	data, ok := input.(outputters.NamedOutputData)
	if !ok {
		return []any{input}, nil
	}

	// Check if enrichment is disabled
	disableEnrichment := l.ArgBool("disable-enrichment", false)
	
	if disableEnrichment {
		l.Logger().Debug("Enrichment disabled, skipping resource enrichment")
		return []any{data}, nil
	}

	// Extract the Azure resource from the data
	resource, ok := data.Data.(output.CloudResource)
	if !ok {
		l.Logger().Debug("Skipping non-CloudResource data in enrichment", "data_type", fmt.Sprintf("%T", data.Data))
		return []any{data}, nil
	}

	// Get template ID from resource properties
	templateID, exists := resource.Properties["templateID"].(string)
	if !exists {
		l.Logger().Debug("No templateID found in resource properties, skipping enrichment", "resource_id", resource.ResourceID)
		return []any{data}, nil
	}

	// Enrich the resource with security testing commands
	commands := l.registry.EnrichResource(ctx, templateID, &resource)

	if len(commands) > 0 {
		l.Logger().Debug("Enriched resource with commands", "resource_id", resource.ResourceID, "template_id", templateID, "command_count", len(commands))

		// Add commands to resource properties
		if resource.Properties == nil {
			resource.Properties = make(map[string]any)
		}
		resource.Properties["commands"] = commands
	}

	// Update the data with the enriched resource
	data.Data = resource
	return []any{data}, nil
}
