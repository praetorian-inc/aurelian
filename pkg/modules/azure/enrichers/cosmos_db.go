package enrichers

import (
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("cosmos_db_public_access", enrichCosmosDB)
}

func enrichCosmosDB(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	cosmosName := result.ResourceName
	if cosmosName == "" {
		return nil, nil
	}

	var endpoint string
	if ep, ok := result.Properties["endpoint"].(string); ok {
		endpoint = ep
	} else {
		endpoint = fmt.Sprintf("https://%s.documents.azure.com", cosmosName)
	}

	discoveryURL := strings.TrimSuffix(endpoint, "/") + "/"
	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", discoveryURL)

	client := NewHTTPClient(10 * time.Second)
	cmd := HTTPProbe(client, discoveryURL, curlEquiv,
		"Test anonymous access to Cosmos DB discovery endpoint",
		"401/403 = authentication required | 200 = anonymous access enabled (misconfiguration) | other = connection/network issues",
	)

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}
