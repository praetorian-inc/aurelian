package enrichers

import (
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("event_grid_domain_public", enrichEventGrid)
}

func enrichEventGrid(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	ep, _ := result.Properties["endpoint"].(string)
	return enrichEventGridPOSTEndpoint(cfg.Context, result.ResourceName, result.Location, ep, "Test Event Grid domain POST endpoint")
}
