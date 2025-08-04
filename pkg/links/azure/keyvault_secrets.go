package azure

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AzureKeyVaultSecretsLink extracts secrets from Azure Key Vaults
type AzureKeyVaultSecretsLink struct {
	*chain.Base
}

func NewAzureKeyVaultSecretsLink(configs ...cfg.Config) chain.Link {
	l := &AzureKeyVaultSecretsLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureKeyVaultSecretsLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureSubscription(),
	}
}

func (l *AzureKeyVaultSecretsLink) Process(resource *model.AzureResource) error {
	// Extract vault URI from resource properties
	vaultURI, err := l.getVaultURI(resource)
	if err != nil {
		return fmt.Errorf("failed to get vault URI: %w", err)
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create Key Vault client
	client, err := azsecrets.NewClient(vaultURI, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Key Vault client: %w", err)
	}

	l.Logger.Debug("Scanning Key Vault secrets", "vault_uri", vaultURI)

	// List secrets (metadata only - requires explicit permission to read values)
	pager := client.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(l.Context())
		if err != nil {
			l.Logger.Error("Failed to list secrets", "error", err.Error())
			break
		}

		for _, secret := range page.Value {
			if secret.ID == nil {
				continue
			}

			// Get secret properties (not the actual secret value for security)
			secretName := l.extractSecretName(string(*secret.ID))
			secretProps, err := client.GetSecret(l.Context(), secretName, "", nil)
			if err != nil {
				l.Logger.Debug("Cannot access secret (insufficient permissions)",
					"secret", secretName,
					"error", err.Error())
				continue
			}

			// Create metadata for scanning (without the actual secret value)
			secretMetadata := map[string]interface{}{
				"id":          *secret.ID,
				"name":        secretName,
				"enabled":     secretProps.Attributes.Enabled,
				"created":     secretProps.Attributes.Created,
				"updated":     secretProps.Attributes.Updated,
				"contentType": secretProps.ContentType,
				"tags":        secretProps.Tags,
			}

			// Convert metadata to JSON for scanning
			metadataContent, err := json.Marshal(secretMetadata)
			if err == nil {
				npInput := jtypes.NPInput{
					Content: string(metadataContent),
					Provenance: jtypes.NPProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.KeyVault/vaults/secrets",
						ResourceID:   fmt.Sprintf("%s/secrets/%s", resource.Key, secretName),
						AccountID:    resource.AccountRef,
					},
				}
				l.Send(npInput)
			}
		}
	}

	return nil
}

func (l *AzureKeyVaultSecretsLink) getVaultURI(resource *model.AzureResource) (string, error) {
	if resource.Properties == nil {
		return "", fmt.Errorf("resource properties are nil")
	}

	if vaultURI, ok := resource.Properties["vaultUri"].(string); ok {
		return vaultURI, nil
	}

	// Construct vault URI from resource name if not in properties
	_, vaultName, err := l.parseKeyVaultResourceID(resource.Key)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("https://%s.vault.azure.net/", vaultName), nil
}

func (l *AzureKeyVaultSecretsLink) parseKeyVaultResourceID(resourceID string) (resourceGroup, vaultName string, err error) {
	parsed, err := helpers.ParseAzureResourceID(resourceID)
	if err != nil {
		return "", "", err
	}

	resourceGroup = parsed["resourceGroups"]
	vaultName = parsed["vaults"]

	if resourceGroup == "" || vaultName == "" {
		return "", "", fmt.Errorf("invalid Key Vault resource ID format")
	}

	return resourceGroup, vaultName, nil
}

func (l *AzureKeyVaultSecretsLink) extractSecretName(secretID string) string {
	// Extract secret name from the secret ID URL
	// Format: https://vault.vault.azure.net/secrets/secretname/version
	if secretID == "" {
		return ""
	}

	// Simple extraction - in practice you'd use proper URL parsing
	parts := strings.Split(secretID, "/")
	if len(parts) >= 5 && parts[3] == "secrets" {
		return parts[4]
	}

	return ""
}
