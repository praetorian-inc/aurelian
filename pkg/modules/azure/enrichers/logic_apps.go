package enrichers

import (
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("logic_apps_public_access", enrichLogicApps)
}

func enrichLogicApps(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	accessEndpoint, _ := result.Properties["accessEndpoint"].(string)
	if accessEndpoint == "" {
		return nil, nil
	}

	accessEndpoint = strings.TrimSuffix(accessEndpoint, "/")
	triggersURL := fmt.Sprintf("%s/triggers?api-version=2016-10-01", accessEndpoint)
	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", triggersURL)

	client := NewHTTPClient(10 * time.Second)
	cmd := HTTPProbe(client, triggersURL, curlEquiv,
		"Test Logic App trigger discovery endpoint",
		"401 = requires SAS token | 403 = forbidden | 200 = triggers accessible (critical)",
	)

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}
