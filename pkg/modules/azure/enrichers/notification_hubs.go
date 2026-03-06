package enrichers

import (
	"fmt"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("notification_hubs_public_access", enrichNotificationHubs)
}

func enrichNotificationHubs(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	namespaceName := result.ResourceName
	if namespaceName == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf("https://%s.servicebus.windows.net", namespaceName)
	client := NewNoRedirectHTTPClient(10 * time.Second)

	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", endpoint)
	mainCmd := HTTPProbe(client, endpoint, curlEquiv,
		"Test if Notification Hubs endpoint is accessible",
		"401 = requires authentication | 403 = forbidden | 404 = not found | 200 = accessible without key (unusual)",
	)

	mgmtURL := fmt.Sprintf("%s/$management", endpoint)
	mgmtCurlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", mgmtURL)
	mgmtCmd := HTTPProbe(client, mgmtURL, mgmtCurlEquiv,
		"Test Notification Hubs namespace management endpoint",
		"401 = requires shared access key | 403 = forbidden | 404 = not found | 200 = accessible",
	)

	return []plugin.AzureEnrichmentCommand{mainCmd, mgmtCmd}, nil
}
