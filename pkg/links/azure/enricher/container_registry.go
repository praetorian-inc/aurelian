package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ContainerRegistryEnricher implements enrichment for Container Registry instances
type ContainerRegistryEnricher struct{}

// TokenResponse represents the OAuth2 token response from ACR
type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (c *ContainerRegistryEnricher) CanEnrich(templateID string) bool {
	return templateID == "container_registries_public_access"
}

// getAnonymousToken attempts to get an anonymous OAuth2 token for the given scope
func (c *ContainerRegistryEnricher) getAnonymousToken(client *http.Client, loginServer, scope string) (string, error) {
	tokenURL := fmt.Sprintf("https://%s/oauth2/token?service=%s&scope=%s",
		loginServer,
		url.QueryEscape(loginServer),
		url.QueryEscape(scope))

	resp, err := client.Get(tokenURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return "", fmt.Errorf("token request failed: HTTP %d, %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %v", err)
	}

	return tokenResp.AccessToken, nil
}

func (c *ContainerRegistryEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract Container Registry name and login server
	registryName := resource.Name
	var loginServer string

	if loginServerProp, exists := resource.Properties["loginServer"].(string); exists {
		loginServer = loginServerProp
	} else {
		loginServer = fmt.Sprintf("%s.azurecr.io", registryName)
	}

	if registryName == "" || loginServer == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Container Registry name or login server",
			ActualOutput: "Error: Registry name or login server is empty",
		})
		return commands
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test 1: OAuth2 Anonymous Token + Repository catalog test (comprehensive anonymous access verification)
	catalogScope := "registry:catalog:*"
	var catalogBody []byte // Store raw body for Test 2

	catalogCommand := Command{
		Command:                   fmt.Sprintf("TOKEN=$(echo -en 'https://%s/oauth2/token?service=%s&scope=%s' | xargs curl -s | jq -r .access_token); curl -H 'Authorization: Bearer '$TOKEN 'https://%s/v2/_catalog'", loginServer, loginServer, catalogScope, loginServer),
		Description:               "Test anonymous OAuth2 token + repository catalog access (definitive anonymous pull test)",
		ExpectedOutputDescription: "Success with repositories list = anonymous pull enabled | Token failure = anonymous access disabled | 401/403 = secured",
	}

	// Attempt to get anonymous token and access catalog
	token, tokenErr := c.getAnonymousToken(client, loginServer, catalogScope)

	if tokenErr != nil {
		catalogCommand.Error = tokenErr.Error()
		catalogCommand.ActualOutput = fmt.Sprintf("Anonymous token request failed: %s", tokenErr.Error())
		catalogCommand.ExitCode = 401
	} else {
		// Use token to access catalog
		catalogURL := fmt.Sprintf("https://%s/v2/_catalog", loginServer)
		req, _ := http.NewRequest("GET", catalogURL, nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		catalogResp, catalogErr := client.Do(req)
		if catalogErr != nil {
			catalogCommand.Error = catalogErr.Error()
			catalogCommand.ActualOutput = fmt.Sprintf("Catalog request failed: %s", catalogErr.Error())
		} else {
			defer catalogResp.Body.Close()
			body, readErr := io.ReadAll(io.LimitReader(catalogResp.Body, 1000))
			if readErr != nil {
				catalogCommand.ActualOutput = fmt.Sprintf("Body read error: %s", readErr.Error())
			} else {
				catalogBody = body // Store raw body for Test 2
				if catalogResp.StatusCode == 200 {
					catalogCommand.ActualOutput = fmt.Sprintf("✓ ANONYMOUS ACCESS CONFIRMED | Repositories: %s", string(body))
				} else {
					catalogCommand.ActualOutput = fmt.Sprintf("Body: %s", string(body))
				}
			}
			catalogCommand.ExitCode = catalogResp.StatusCode
		}
	}

	commands = append(commands, catalogCommand)

	// Test 2: Anonymous Docker pull attempt using first repository from Test 1
	var repositoryName string = "[REPOSITORY_NAME]" // Default fallback

	// Try to extract first repository from Test 1's raw JSON response
	if catalogCommand.ExitCode == 200 && len(catalogBody) > 0 {
		// Parse the raw JSON response to get the first repository
		var catalogResponse struct {
			Repositories []string `json:"repositories"`
		}

		if err := json.Unmarshal(catalogBody, &catalogResponse); err == nil && len(catalogResponse.Repositories) > 0 {
			repositoryName = catalogResponse.Repositories[0]
		}
	}

	dockerPullCommand := Command{
		Command:                   fmt.Sprintf("docker pull %s/%s", loginServer, repositoryName),
		Description:               fmt.Sprintf("Test anonymous Docker pull of repository: %s", repositoryName),
		ExpectedOutputDescription: "Pull successful = anonymous access enabled | Authentication required = secured | Not found = repository doesn't exist",
		ActualOutput:              "Manual execution required - requires Docker CLI",
	}
	commands = append(commands, dockerPullCommand)

	// Test 3: Azure CLI registry information
	azCliCommand := Command{
		Command:                   fmt.Sprintf("az acr show --name %s --query '{loginServer:loginServer,adminUserEnabled:adminUserEnabled,publicNetworkAccess:publicNetworkAccess,anonymousPullEnabled:anonymousPullEnabled}'", registryName),
		Description:               "Azure CLI command to check registry configuration (including anonymous pull setting)",
		ExpectedOutputDescription: "Registry details = accessible via Azure API | Error = access denied or registry not found",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}

	commands = append(commands, azCliCommand)

	return commands
}
