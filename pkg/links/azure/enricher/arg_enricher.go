package enricher

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ARGEnrichmentLink enriches Azure resources with additional security testing commands
type ARGEnrichmentLink struct {
	*chain.Base
	registry *EnrichmentRegistry
}

// NewARGEnrichmentLink creates a new enrichment link with all available enrichers
func NewARGEnrichmentLink(configs ...cfg.Config) chain.Link {
	l := &ARGEnrichmentLink{
		registry: NewEnrichmentRegistry(),
	}
	l.Base = chain.NewBase(l, configs...)
	return l
}

// Params returns the parameters required by this link
func (l *ARGEnrichmentLink) Params() []cfg.Param {
	return []cfg.Param{}
}

// Process enriches Azure resources with security testing commands based on template ID
func (l *ARGEnrichmentLink) Process(data outputters.NamedOutputData) error {
	// Extract the Azure resource from the data
	resource, ok := data.Data.(model.AzureResource)
	if !ok {
		l.Logger.Debug("Skipping non-AzureResource data in enrichment", "data_type", fmt.Sprintf("%T", data.Data))
		l.Send(data)
		return nil
	}

	// Get template ID from resource properties
	templateID, exists := resource.Properties["templateID"].(string)
	if !exists {
		l.Logger.Debug("No templateID found in resource properties, skipping enrichment", "resource_id", resource.Key)
		l.Send(data)
		return nil
	}

	// Enrich the resource with security testing commands
	commands := l.registry.EnrichResource(l.Context(), templateID, &resource)

	if len(commands) > 0 {
		l.Logger.Debug("Enriched resource with commands", "resource_id", resource.Key, "template_id", templateID, "command_count", len(commands))

		// Add commands to resource properties
		if resource.Properties == nil {
			resource.Properties = make(map[string]any)
		}
		resource.Properties["commands"] = commands
	}

	// Send the enriched resource
	l.Send(data)
	return nil
}
