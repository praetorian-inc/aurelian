package enrichers

import (
	"fmt"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("container_apps_public_access", enrichContainerApps)
}

func enrichContainerApps(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	var fqdn string
	if v, ok := result.Properties["ingressFqdn"].(string); ok && v != "" {
		fqdn = v
	} else if v, ok := result.Properties["latestRevisionFqdn"].(string); ok && v != "" {
		fqdn = v
	}

	if fqdn == "" {
		return nil, nil
	}

	client := NewNoRedirectHTTPClient(10 * time.Second)

	testURL := fmt.Sprintf("https://%s", fqdn)
	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", testURL)

	cmd := HTTPProbe(client, testURL, curlEquiv,
		"Test if Container App FQDN is accessible",
		"200 = app responding | 401/403 = auth required | 502 = backend error | Timeout = not reachable",
	)

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}
