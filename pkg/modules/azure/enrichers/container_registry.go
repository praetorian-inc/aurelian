package enrichers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("container_registries_public_access", enrichContainerRegistry)
	plugin.RegisterAzureEnricher("acr_anonymous_pull_access", enrichContainerRegistry)
}

// tokenResponse represents the OAuth2 token response from ACR.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

func enrichContainerRegistry(_ plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	registryName := result.ResourceName

	var loginServer string
	if ls, ok := result.Properties["loginServer"].(string); ok {
		loginServer = ls
	} else {
		loginServer = fmt.Sprintf("%s.azurecr.io", registryName)
	}

	if registryName == "" || loginServer == "" {
		return []plugin.AzureEnrichmentCommand{{
			Description:  "Missing Container Registry name or login server",
			ActualOutput: "Error: Registry name or login server is empty",
		}}, nil
	}

	client := NewHTTPClient(10 * time.Second)

	// Test 1: OAuth2 anonymous token + repository catalog access
	catalogScope := "registry:catalog:*"
	var catalogBody []byte

	catalogCmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("TOKEN=$(echo -en 'https://%s/oauth2/token?service=%s&scope=%s' | xargs curl -s | jq -r .access_token); curl -H 'Authorization: Bearer '$TOKEN 'https://%s/v2/_catalog'", loginServer, loginServer, catalogScope, loginServer),
		Description:               "Test anonymous OAuth2 token + repository catalog access (definitive anonymous pull test)",
		ExpectedOutputDescription: "Success with repositories list = anonymous pull enabled | Token failure = anonymous access disabled | 401/403 = secured",
	}

	token, tokenErr := getAnonymousACRToken(client, loginServer, catalogScope)
	if tokenErr != nil {
		catalogCmd.Error = tokenErr.Error()
		catalogCmd.ActualOutput = fmt.Sprintf("Anonymous token request failed: %s", tokenErr.Error())
		catalogCmd.ExitCode = 401
	} else {
		catalogURL := fmt.Sprintf("https://%s/v2/_catalog", loginServer)
		req, _ := http.NewRequest("GET", catalogURL, nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		catalogResp, catalogErr := client.Do(req)
		if catalogErr != nil {
			catalogCmd.Error = catalogErr.Error()
			catalogCmd.ActualOutput = fmt.Sprintf("Catalog request failed: %s", catalogErr.Error())
			catalogCmd.ExitCode = 1
		} else {
			defer catalogResp.Body.Close()
			body, readErr := io.ReadAll(io.LimitReader(catalogResp.Body, 1000))
			if readErr != nil {
				catalogCmd.ActualOutput = fmt.Sprintf("Body read error: %s", readErr.Error())
			} else {
				catalogBody = body
				if catalogResp.StatusCode == 200 {
					catalogCmd.ActualOutput = fmt.Sprintf("ANONYMOUS ACCESS CONFIRMED | Repositories: %s", string(body))
				} else {
					catalogCmd.ActualOutput = fmt.Sprintf("Body: %s", string(body))
				}
			}
			catalogCmd.ExitCode = catalogResp.StatusCode
		}
	}

	commands := []plugin.AzureEnrichmentCommand{catalogCmd}

	// Test 2: Anonymous Docker pull attempt using first repository from Test 1
	repositoryName := "[REPOSITORY_NAME]"
	if catalogCmd.ExitCode == 200 && len(catalogBody) > 0 {
		var catalogResponse struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.Unmarshal(catalogBody, &catalogResponse); err == nil && len(catalogResponse.Repositories) > 0 {
			repositoryName = catalogResponse.Repositories[0]
		}
	}

	dockerPullCmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("docker pull %s/%s", loginServer, repositoryName),
		Description:               fmt.Sprintf("Test anonymous Docker pull of repository: %s", repositoryName),
		ExpectedOutputDescription: "Pull successful = anonymous access enabled | Authentication required = secured | Not found = repository doesn't exist",
		ActualOutput:              "Manual execution required - requires Docker CLI",
	}
	commands = append(commands, dockerPullCmd)

	// Test 3: Azure CLI registry information
	azCliCmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("az acr show --name %s --query '{loginServer:loginServer,adminUserEnabled:adminUserEnabled,publicNetworkAccess:publicNetworkAccess,anonymousPullEnabled:anonymousPullEnabled}'", registryName),
		Description:               "Azure CLI command to check registry configuration (including anonymous pull setting)",
		ExpectedOutputDescription: "Registry details = accessible via Azure API | Error = access denied or registry not found",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
	commands = append(commands, azCliCmd)

	return commands, nil
}

// getAnonymousACRToken attempts to get an anonymous OAuth2 token for the given scope.
func getAnonymousACRToken(client *http.Client, loginServer, scope string) (string, error) {
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

	var tok tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("failed to decode token response: %v", err)
	}

	return tok.AccessToken, nil
}
