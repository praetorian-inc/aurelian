package enrichers

import (
	"fmt"
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
		return nil, nil
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
	return StatusCodeHTTPProbe(client, endpoint,
		fmt.Sprintf("curl -i '%s' --max-time 10", endpoint),
		"Test if Cognitive Services endpoint is accessible",
		"401 = requires authentication (API key) | 403 = forbidden | 404 = not found | 200 = accessible without key (unusual)",
		1000, 500)
}

func cognitiveTestOpenAIDeployments(client *http.Client, baseEndpoint string) plugin.AzureEnrichmentCommand {
	deploymentsURL := fmt.Sprintf("%s/openai/deployments", baseEndpoint)
	return StatusCodeHTTPProbe(client, deploymentsURL,
		fmt.Sprintf("curl -i '%s' --max-time 10", deploymentsURL),
		"Test OpenAI deployments endpoint (lists available models)",
		"401 = requires authentication | 403 = forbidden | 404 = not found | 200 = deployments accessible",
		1500, 800)
}
