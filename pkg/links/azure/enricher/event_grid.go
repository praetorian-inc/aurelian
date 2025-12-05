package enricher

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
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
	if location == "" {
		if loc, ok := resource.Properties["location"].(string); ok && loc != "" {
			location = loc
		}
	}

	var eventGridEndpoint string
	if endpoint, exists := resource.Properties["endpoint"].(string); exists && endpoint != "" {
		eventGridEndpoint = endpoint
		if !strings.HasSuffix(eventGridEndpoint, "/api/events") {
			eventGridEndpoint = strings.TrimSuffix(eventGridEndpoint, "/") + "/api/events"
		}
	} else {
		if location == "" {
			return commands
		}
		if eventGridName == "" {
			commands = append(commands, Command{
				Command:      "",
				Description:  "Missing Event Grid name",
				ActualOutput: "Error: Event Grid name is empty",
			})
			return commands
		}
		normalizedLocation := strings.TrimSpace(strings.ToLower(location))
		eventGridEndpoint = fmt.Sprintf("https://%s.%s-1.eventgrid.azure.net/api/events", eventGridName, normalizedLocation)
	}
	client := &http.Client{Timeout: 10 * time.Second}

	body := bytes.NewBuffer([]byte("[]"))
	req, err := http.NewRequestWithContext(ctx, "POST", eventGridEndpoint, body)
	if err != nil {
		return commands
	}
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := client.Do(req)

	postCommand := Command{
		Command:                   fmt.Sprintf("curl -X POST -H 'Content-Type: application/json' -d '[]' -i '%s' --max-time 10", eventGridEndpoint),
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
