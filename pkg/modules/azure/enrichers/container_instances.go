package enrichers

import (
	"fmt"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("container_instances_public_access", enrichContainerInstances)
}

func enrichContainerInstances(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	resourceName := result.ResourceName
	if resourceName == "" {
		return nil, nil
	}

	ipAddress, _ := result.Properties["ipAddress"].(string)
	if ipAddress == "" {
		return nil, nil
	}

	client := NewHTTPClient(10 * time.Second)

	testURL := fmt.Sprintf("http://%s", ipAddress)
	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", testURL)

	cmd := HTTPProbe(client, testURL, curlEquiv,
		"Test HTTP connectivity to container instance public IP",
		"200 = container app responding | Connection refused = port not open | Timeout = IP not reachable",
	)

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}
