package enrichers

import (
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("key_vault_public_access", enrichKeyVault)
}

func enrichKeyVault(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	keyVaultName := result.ResourceName
	if keyVaultName == "" {
		return nil, nil
	}

	var vaultURI string
	if v, ok := result.Properties["vaultUri"].(string); ok {
		vaultURI = strings.TrimSuffix(v, "/")
	} else {
		vaultURI = fmt.Sprintf("https://%s.vault.azure.net", keyVaultName)
	}

	discoveryURL := fmt.Sprintf("%s/keys?api-version=7.4", vaultURI)
	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", discoveryURL)

	client := NewHTTPClient(10 * time.Second)
	cmd := HTTPProbe(client, discoveryURL, curlEquiv,
		"Test Key Vault keys listing endpoint",
		"401 = authentication required | 200 = anonymous access (critical issue) | 403 = access denied",
	)

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}
