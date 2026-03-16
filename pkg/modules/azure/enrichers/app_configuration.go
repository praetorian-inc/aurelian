package enrichers

import (
	"fmt"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("app_configuration_public_access", enrichAppConfiguration)
}

func enrichAppConfiguration(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	name := result.ResourceName
	if name == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf("https://%s.azconfig.io", name)
	client := NewHTTPClient(10 * time.Second)

	mainURL := endpoint
	mainCurl := fmt.Sprintf("curl -i '%s' --max-time 10", mainURL)
	mainCmd := HTTPProbe(client, mainURL, mainCurl,
		"Test if App Configuration endpoint is accessible",
		"401 = requires authentication | 403 = forbidden | 200 = accessible without key (unusual)",
	)

	kvURL := fmt.Sprintf("%s/kv", endpoint)
	kvCurl := fmt.Sprintf("curl -i '%s' --max-time 10", kvURL)
	kvCmd := HTTPProbe(client, kvURL, kvCurl,
		"Test App Configuration key-values endpoint",
		"401 = requires API key | 403 = forbidden | 200 = key-values accessible",
	)

	return []plugin.AzureEnrichmentCommand{mainCmd, kvCmd}, nil
}
