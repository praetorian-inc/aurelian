package enrichers

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("event_grid_topics_public_access", enrichEventGridTopics)
}

func enrichEventGridTopics(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	topicName := result.ResourceName
	location := result.Location

	var topicEndpoint string
	if ep, ok := result.Properties["endpoint"].(string); ok && ep != "" {
		topicEndpoint = ep
		if !strings.HasSuffix(topicEndpoint, "/api/events") {
			topicEndpoint = strings.TrimSuffix(topicEndpoint, "/") + "/api/events"
		}
	} else {
		if location == "" || topicName == "" {
			return nil, nil
		}
		normalizedLocation := strings.TrimSpace(strings.ToLower(location))
		topicEndpoint = fmt.Sprintf("https://%s.%s-1.eventgrid.azure.net/api/events", topicName, normalizedLocation)
	}

	client := NewHTTPClient(10 * time.Second)

	body := bytes.NewBuffer([]byte("[]"))
	req, err := http.NewRequestWithContext(cfg.Context, "POST", topicEndpoint, body)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Content-Type", "application/json")

	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("curl -X POST -H 'Content-Type: application/json' -d '[]' -i '%s' --max-time 10", topicEndpoint),
		Description:               "Test Event Grid Topic POST endpoint",
		ExpectedOutputDescription: "401/405 = publicly accessible but authentication required | 403 = blocked via firewall rules",
	}

	resp, err := client.Do(req)
	if err != nil {
		cmd.ExitCode = 1
		cmd.Error = err.Error()
	} else {
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		cmd.ActualOutput = fmt.Sprintf("HTTP %d", resp.StatusCode)
		cmd.ExitCode = 0
	}

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}
