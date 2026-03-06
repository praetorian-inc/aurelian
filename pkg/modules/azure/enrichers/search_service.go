package enrichers

import (
	"fmt"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("search_service_public_access", enrichSearchService)
}

func enrichSearchService(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	serviceName := result.ResourceName
	if serviceName == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf("https://%s.search.windows.net", serviceName)
	client := NewNoRedirectHTTPClient(10 * time.Second)

	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", endpoint)
	mainCmd := HTTPProbe(client, endpoint, curlEquiv,
		"Test if Search Service endpoint is accessible",
		"401/403 = authentication required (API key needed) | 404 = not found | 200 = accessible without key (unusual)",
	)

	indexesURL := fmt.Sprintf("%s/indexes", endpoint)
	indexesCurlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", indexesURL)
	indexesCmd := HTTPProbe(client, indexesURL, indexesCurlEquiv,
		"Test Search Service indexes endpoint (enumeration test)",
		"401/403 = authentication required (API key needed) | 404 = not found | 200 = indexes accessible",
	)

	return []plugin.AzureEnrichmentCommand{mainCmd, indexesCmd}, nil
}
