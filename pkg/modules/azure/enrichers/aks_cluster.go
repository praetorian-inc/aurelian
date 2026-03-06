package enrichers

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("aks_public_access", enrichAKSCluster)
}

func enrichAKSCluster(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	clusterName := result.ResourceName
	if clusterName == "" {
		return nil, nil
	}

	fqdn, _ := result.Properties["fqdn"].(string)
	if fqdn == "" {
		return nil, nil
	}

	testURL := fmt.Sprintf("https://%s", fqdn)
	curlEquiv := fmt.Sprintf("curl -k -i '%s' --max-time 10", testURL)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	cmd := HTTPProbe(client, testURL, curlEquiv,
		fmt.Sprintf("Test direct HTTP access to Kubernetes endpoint: %s", fqdn),
		"200 = anonymous access enabled | 401/403 = authentication required | timeout = blocked",
	)

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}
