package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AzureKeyVaultSecretsLink extracts secrets from Azure Key Vaults
type AzureKeyVaultSecretsLink struct {
	*base.NativeAzureLink
}

func NewAzureKeyVaultSecretsLink(args map[string]any) *AzureKeyVaultSecretsLink {
	return &AzureKeyVaultSecretsLink{
		NativeAzureLink: base.NewNativeAzureLink("azure-keyvault-secrets", args),
	}
}

func (l *AzureKeyVaultSecretsLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		options.AzureSubscription(),
	}
}

func (l *AzureKeyVaultSecretsLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		if resourceValue, ok := input.(output.CloudResource); ok {
			resource = &resourceValue
		} else {
			return nil, fmt.Errorf("expected *output.CloudResource or output.CloudResource, got %T", input)
		}
	}

	// Extract vault URI from resource properties
	vaultURI, err := l.getVaultURI(resource)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault URI: %w", err)
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create Key Vault client
	client, err := azsecrets.NewClient(vaultURI, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Vault client: %w", err)
	}

	l.Logger().Debug("Scanning Key Vault secrets", "vault_uri", vaultURI)

	// List secrets (metadata only - requires explicit permission to read values)
	pager := client.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			l.Logger().Error("Failed to list secrets", "error", err.Error())
			break
		}

		for _, secret := range page.Value {
			if secret.ID == nil {
				continue
			}

			// Get secret properties (not the actual secret value for security)
			secretName := l.extractSecretName(string(*secret.ID))
			secretProps, err := client.GetSecret(ctx, secretName, "", nil)
			if err != nil {
				l.Logger().Debug("Cannot access secret (insufficient permissions)",
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
				npInput := types.NpInput{
					Content: string(metadataContent),
					Provenance: types.NpProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.KeyVault/vaults/secrets",
						ResourceID:   fmt.Sprintf("%s/secrets/%s", resource.ResourceID, secretName),
						AccountID:    resource.AccountRef,
					},
				}
				l.Send(npInput)
			}
		}
	}

	return l.Outputs(), nil
}

func (l *AzureKeyVaultSecretsLink) getVaultURI(resource *output.CloudResource) (string, error) {
	if resource.Properties == nil {
		return "", fmt.Errorf("resource properties are nil")
	}

	if vaultURI, ok := resource.Properties["vaultUri"].(string); ok {
		return vaultURI, nil
	}

	// Construct vault URI from resource name if not in properties
	_, vaultName, err := l.parseKeyVaultResourceID(resource.ResourceID)
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
