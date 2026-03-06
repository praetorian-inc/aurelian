package enrichers

import (
	"fmt"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("iot_hub_public_access", enrichIoTHub)
}

func enrichIoTHub(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	iotHubName := result.ResourceName
	if iotHubName == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf("https://%s.azure-devices.net", iotHubName)
	registryURL := fmt.Sprintf("%s/devices?api-version=2021-04-12", endpoint)
	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", registryURL)

	client := NewNoRedirectHTTPClient(10 * time.Second)
	cmd := HTTPProbe(client, registryURL, curlEquiv,
		"Test IoT Hub device registry endpoint (enumeration test)",
		"401 = authentication required (endpoint publicly reachable) | 403 = forbidden | 404 = not found | 200 = devices accessible",
	)

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}
