package enrichers

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("cognitive_services_public_access", enrichCognitiveServices)
}

func enrichCognitiveServices(_ plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	serviceName := result.ResourceName
	if serviceName == "" {
		return []plugin.AzureEnrichmentCommand{{
			Description:  "Missing Cognitive Services name",
			ActualOutput: "Error: Cognitive Services name is empty",
		}}, nil
	}

	// Detect if this is an OpenAI service
	kind := ""
	if k, ok := result.Properties["kind"].(string); ok {
		kind = k
	}

	var cognitiveEndpoint string
	if kind == "OpenAI" {
		cognitiveEndpoint = fmt.Sprintf("https://%s.openai.azure.com", serviceName)
	} else {
		cognitiveEndpoint = fmt.Sprintf("https://%s.cognitiveservices.azure.com", serviceName)
	}

	client := NewHTTPClient(10 * time.Second)

	var commands []plugin.AzureEnrichmentCommand

	// Test 1: Check if endpoint is accessible
	endpointCmd := cognitiveTestEndpointAccess(client, cognitiveEndpoint)
	commands = append(commands, endpointCmd)

	// Test 2: Test OpenAI-specific endpoint if this is an OpenAI service
	if kind == "OpenAI" {
		openaiCmd := cognitiveTestOpenAIDeployments(client, cognitiveEndpoint)
		commands = append(commands, openaiCmd)
	}

	return commands, nil
}

func cognitiveTestEndpointAccess(client *http.Client, endpoint string) plugin.AzureEnrichmentCommand {
	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", endpoint),
		Description:               "Test if Cognitive Services endpoint is accessible",
		ExpectedOutputDescription: "401 = requires authentication (API key) | 403 = forbidden | 404 = not found | 200 = accessible without key (unusual)",
	}

	resp, err := client.Get(endpoint)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
	cmd.ActualOutput = fmt.Sprintf("Status: %d, Body preview: %s", resp.StatusCode, TruncateString(string(body), 500))
	cmd.ExitCode = resp.StatusCode

	return cmd
}

func cognitiveTestOpenAIDeployments(client *http.Client, baseEndpoint string) plugin.AzureEnrichmentCommand {
	deploymentsURL := fmt.Sprintf("%s/openai/deployments", baseEndpoint)

	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", deploymentsURL),
		Description:               "Test OpenAI deployments endpoint (lists available models)",
		ExpectedOutputDescription: "401 = requires authentication | 403 = forbidden | 404 = not found | 200 = deployments accessible",
	}

	resp, err := client.Get(deploymentsURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1500))
	cmd.ActualOutput = fmt.Sprintf("Status: %d, Body preview: %s", resp.StatusCode, TruncateString(string(body), 800))
	cmd.ExitCode = resp.StatusCode

	return cmd
}
