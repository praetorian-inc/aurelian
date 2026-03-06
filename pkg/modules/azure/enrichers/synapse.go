package enrichers

import (
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("synapse_public_access", enrichSynapse)
}

func enrichSynapse(_ plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	workspaceName := result.ResourceName
	if workspaceName == "" {
		return []plugin.AzureEnrichmentCommand{{
			Description:  "Missing Synapse workspace name",
			ActualOutput: "Error: Synapse workspace name is empty",
		}}, nil
	}

	resourceGroup := ParseResourceGroup(result.ResourceID)

	// Extract connectivity endpoints from properties
	var devEndpoint string
	var sqlEndpoint string
	if result.Properties != nil {
		if endpoints, ok := result.Properties["connectivityEndpoints"].(map[string]interface{}); ok {
			if dev, ok := endpoints["dev"].(string); ok && dev != "" {
				devEndpoint = dev
			}
			if sql, ok := endpoints["sql"].(string); ok && sql != "" {
				sqlEndpoint = sql
			}
		}
	}

	// Ensure endpoints have https:// scheme
	if devEndpoint != "" && !strings.HasPrefix(devEndpoint, "https://") && !strings.HasPrefix(devEndpoint, "http://") {
		devEndpoint = "https://" + devEndpoint
	}
	if sqlEndpoint != "" && !strings.HasPrefix(sqlEndpoint, "https://") && !strings.HasPrefix(sqlEndpoint, "http://") {
		sqlEndpoint = "https://" + sqlEndpoint
	}

	// Construct dev endpoint if not found in properties
	if devEndpoint == "" {
		devEndpoint = fmt.Sprintf("https://%s.dev.azuresynapse.net", workspaceName)
	}

	// Construct SQL on-demand endpoint if not found in properties
	if sqlEndpoint == "" {
		sqlEndpoint = fmt.Sprintf("https://%s-ondemand.sql.azuresynapse.net", workspaceName)
	}

	client := NewHTTPClient(10 * time.Second)

	var commands []plugin.AzureEnrichmentCommand

	// Test dev endpoint
	devCmd := HTTPProbe(client, devEndpoint,
		fmt.Sprintf("curl -i '%s' --max-time 10", devEndpoint),
		"Test if Synapse development endpoint is accessible",
		"401 = requires Azure AD authentication | 403 = forbidden | 200 = accessible (unusual)",
	)
	commands = append(commands, devCmd)

	// Test SQL endpoint
	sqlCmd := HTTPProbe(client, sqlEndpoint,
		fmt.Sprintf("curl -i '%s' --max-time 10", sqlEndpoint),
		"Test Synapse SQL on-demand endpoint accessibility",
		"Connection response = SQL endpoint reachable | Timeout = not accessible",
	)
	commands = append(commands, sqlCmd)

	// Azure CLI command for manual inspection
	if resourceGroup != "" {
		cliCmd := plugin.AzureEnrichmentCommand{
			Command:                   fmt.Sprintf("az synapse workspace show --name %s --resource-group %s", workspaceName, resourceGroup),
			Description:               "Azure CLI command to show Synapse workspace details",
			ExpectedOutputDescription: "Workspace details = accessible via Azure API | Error = access denied",
			ActualOutput:              "Manual execution required - requires Azure CLI authentication",
		}
		commands = append(commands, cliCmd)
	}

	return commands, nil
}
