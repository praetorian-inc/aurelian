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

// KeyVaultEnricher implements enrichment for Key Vault instances
type KeyVaultEnricher struct{}

func (k *KeyVaultEnricher) CanEnrich(templateID string) bool {
	return templateID == "key_vault_public_access"
}

func (k *KeyVaultEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	keyVaultName := resource.Name
	var vaultURI string

	if vaultURIProp, exists := resource.Properties["vaultUri"].(string); exists {
		vaultURI = strings.TrimSuffix(vaultURIProp, "/")
	} else {
		vaultURI = fmt.Sprintf("https://%s.vault.azure.net", keyVaultName)
	}

	if keyVaultName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Key Vault name",
			ActualOutput: "Error: Key Vault name is empty",
		})
		return commands
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Test 1: Key Vault discovery endpoint
	discoveryURL := fmt.Sprintf("%s/keys?api-version=7.4", vaultURI)
	resp, err := client.Get(discoveryURL)

	discoveryCommand := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", discoveryURL),
		Description:               "Test Key Vault keys listing endpoint",
		ExpectedOutputDescription: "401 = authentication required | 200 = anonymous access (critical issue) | 403 = access denied",
	}

	if err != nil {
		discoveryCommand.Error = err.Error()
		discoveryCommand.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
	} else {
		defer resp.Body.Close()
		// Read response body
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1000))
		if readErr != nil {
			discoveryCommand.ActualOutput = fmt.Sprintf("Body read error: %s", readErr.Error())
		} else {
			discoveryCommand.ActualOutput = fmt.Sprintf("Body: %s", string(body))
		}
		discoveryCommand.ExitCode = resp.StatusCode
	}

	commands = append(commands, discoveryCommand)

	return commands
}
