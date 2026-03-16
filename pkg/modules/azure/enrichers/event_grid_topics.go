package enrichers

import (
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("event_grid_topics_public_access", enrichEventGridTopics)
}

func enrichEventGridTopics(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	ep, _ := result.Properties["endpoint"].(string)
	return enrichEventGridPOSTEndpoint(cfg.Context, result.ResourceName, result.Location, ep, "Test Event Grid Topic POST endpoint")
}
