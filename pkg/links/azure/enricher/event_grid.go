package enricher

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// EventGridEnricher implements enrichment for Event Grid instances
type EventGridEnricher struct{}

func (e *EventGridEnricher) CanEnrich(templateID string) bool {
	return templateID == "event_grid_domain_public"
}

func (e *EventGridEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	eventGridName := resource.Name
	location := resource.Region
	if eventGridName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Event Grid name",
			ActualOutput: "Error: Event Grid name is empty",
		})
		return commands
	}

	// Construct Event Grid endpoint
	eventGridEndpoint := fmt.Sprintf("https://%s.%s-1.eventgrid.azure.net", eventGridName, location)
	client := &http.Client{Timeout: 10 * time.Second}

	// Test 1: Event Grid topic endpoint
	resp, err := client.Post(eventGridEndpoint+"/api/events", "application/json", nil)

	postCommand := Command{
		Command:                   fmt.Sprintf("curl -i '%s/api/events' --max-time 10", eventGridEndpoint),
		Description:               "Test Event Grid domain POST endpoint",
		ExpectedOutputDescription: "401/405 = publicly accessible but authentication required | 403 = blocked via firewall rules",
	}

	if err != nil {
		postCommand.Error = err.Error()
		postCommand.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
	} else {
		defer resp.Body.Close()
		postCommand.ActualOutput = fmt.Sprintf("HTTP %d", resp.StatusCode)
		postCommand.ExitCode = resp.StatusCode
	}

	commands = append(commands, postCommand)

	// Test 2: Azure CLI Event Grid test
	commands = append(commands, Command{
		Command:                   fmt.Sprintf("az eventgrid domain show --name %s --resource-group %s", eventGridName, resource.ResourceGroup),
		Description:               "Azure CLI command to show Event Grid domain details",
		ExpectedOutputDescription: "Domain details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	})

	return commands
}
