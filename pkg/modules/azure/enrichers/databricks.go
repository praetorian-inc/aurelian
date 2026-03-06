package enrichers

import (
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("databricks_public_access", enrichDatabricks)
}

func enrichDatabricks(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	if result.ResourceName == "" {
		return nil, nil
	}

	var workspaceURL string
	if u, ok := result.Properties["workspaceUrl"].(string); ok && u != "" {
		workspaceURL = strings.TrimSuffix(u, "/")
		if !strings.HasPrefix(workspaceURL, "https://") {
			workspaceURL = "https://" + workspaceURL
		}
	}
	if workspaceURL == "" {
		return nil, nil
	}

	client := NewNoRedirectHTTPClient(10 * time.Second)

	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", workspaceURL)
	cmd := HTTPProbe(client, workspaceURL, curlEquiv,
		"Test if Databricks workspace is accessible",
		"403 = requires Azure AD authentication | 302 = redirect to login | 200 = workspace accessible",
	)

	apiURL := fmt.Sprintf("%s/api/2.0/clusters/list", workspaceURL)
	apiCurlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", apiURL)
	apiCmd := HTTPProbe(client, apiURL, apiCurlEquiv,
		"Test Databricks REST API endpoint",
		"401/403 = requires authentication token | 200 = API accessible (critical)",
	)

	return []plugin.AzureEnrichmentCommand{cmd, apiCmd}, nil
}
