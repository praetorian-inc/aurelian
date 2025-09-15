package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// CosmosDBEnricher implements enrichment for Cosmos DB accounts
type CosmosDBEnricher struct{}

func (c *CosmosDBEnricher) CanEnrich(templateID string) bool {
	return templateID == "cosmos_db_public_access"
}

func (c *CosmosDBEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract Cosmos DB account name and endpoint
	cosmosName := resource.Name
	var endpoint string

	if endpointProp, exists := resource.Properties["endpoint"].(string); exists {
		endpoint = endpointProp
	} else {
		// Construct standard endpoint if not provided
		endpoint = fmt.Sprintf("https://%s.documents.azure.com", cosmosName)
	}

	if cosmosName == "" || endpoint == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Cosmos DB account name or endpoint",
			ActualOutput: "Error: Cosmos DB name or endpoint is empty",
		})
		return commands
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test 1: Discovery endpoint for anonymous access
	discoveryURL := strings.TrimSuffix(endpoint, "/") + "/"

	resp, err := client.Get(discoveryURL)

	discoveryCommand := fmt.Sprintf("curl -i '%s' --max-time 10", discoveryURL)
	command1 := Command{
		Command:                   discoveryCommand,
		Description:               "Test anonymous access to Cosmos DB discovery endpoint",
		ExpectedOutputDescription: "401/403 = authentication required | 200 = anonymous access enabled (misconfiguration) | other = connection/network issues",
	}

	if err != nil {
		command1.Error = err.Error()
		command1.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
	} else {
		defer resp.Body.Close()
		// Read response body (limit to first 1000 characters for safety)
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1000))
		if readErr != nil {
			command1.ActualOutput = fmt.Sprintf("Body read error: %s", readErr.Error())
		} else {
			command1.ActualOutput = fmt.Sprintf("Body: %s", string(body))
		}
		command1.ExitCode = resp.StatusCode
	}

	commands = append(commands, command1)

	return commands
}
