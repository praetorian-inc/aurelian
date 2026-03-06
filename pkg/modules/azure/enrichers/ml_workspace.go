package enrichers

import (
	"fmt"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("ml_workspace_public_access", enrichMLWorkspace)
}

func enrichMLWorkspace(_ plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	workspaceName := result.ResourceName
	resourceGroup := ParseResourceGroup(result.ResourceID)

	var commands []plugin.AzureEnrichmentCommand

	// Extract workspace-specific notebook FQDN from properties
	notebookFqdn := ""
	if result.Properties != nil {
		if nbFqdn, ok := result.Properties["notebookFqdn"].(string); ok && nbFqdn != "" {
			notebookFqdn = nbFqdn
		}
	}

	// Test workspace-specific notebook endpoint
	if notebookFqdn != "" {
		notebookURL := fmt.Sprintf("https://%s", notebookFqdn)
		client := NewHTTPClient(10 * time.Second)

		cmd := HTTPProbe(client, notebookURL,
			fmt.Sprintf("curl -i '%s' --max-time 10", notebookURL),
			"Test workspace-specific notebook endpoint accessibility",
			"401 = authentication required (workspace publicly reachable) | 403 = forbidden | Timeout = not publicly accessible",
		)
		commands = append(commands, cmd)
	}

	// Azure CLI command for manual inspection
	if workspaceName != "" && resourceGroup != "" {
		cliCmd := plugin.AzureEnrichmentCommand{
			Command:                   fmt.Sprintf("az ml workspace show --name %s --resource-group %s", workspaceName, resourceGroup),
			Description:               "Azure CLI command to show ML workspace details",
			ExpectedOutputDescription: "Workspace details = accessible via Azure API | Error = access denied",
			ActualOutput:              "Manual execution required - requires Azure CLI authentication",
		}
		commands = append(commands, cliCmd)
	} else {
		commands = append(commands, plugin.AzureEnrichmentCommand{
			Description:  "Azure CLI command to show ML workspace details",
			ActualOutput: "Error: workspace name or resource group is empty",
		})
	}

	return commands, nil
}
