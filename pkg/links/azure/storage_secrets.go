package azure

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AzureStorageSecretsLink extracts secrets from Azure Storage Accounts
type AzureStorageSecretsLink struct {
	*chain.Base
}

func NewAzureStorageSecretsLink(configs ...cfg.Config) chain.Link {
	l := &AzureStorageSecretsLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureStorageSecretsLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureSubscription(),
	}
}

func (l *AzureStorageSecretsLink) Process(resource *model.AzureResource) error {
	subscriptionID := resource.AccountRef

	// Extract resource group and storage account name from resource ID
	resourceGroup, accountName, err := l.parseStorageResourceID(resource.Key)
	if err != nil {
		return fmt.Errorf("failed to parse storage account resource ID: %w", err)
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create storage accounts client
	client, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create storage accounts client: %w", err)
	}

	l.Logger.Debug("Scanning storage account keys",
		"resource_group", resourceGroup,
		"account_name", accountName)

	// Get storage account keys (requires appropriate permissions)
	keys, err := client.ListKeys(l.Context(), resourceGroup, accountName, nil)
	if err != nil {
		l.Logger.Error("Failed to get storage account keys", "error", err.Error())
		return nil // Don't fail the whole process
	}

	// Convert keys to JSON for scanning (metadata only)
	if keys.Keys != nil {
		keysMetadata := make([]map[string]interface{}, 0, len(keys.Keys))
		for _, key := range keys.Keys {
			keyMetadata := map[string]interface{}{
				"keyName":      key.KeyName,
				"permissions":  key.Permissions,
				"creationTime": key.CreationTime,
			}
			// Don't include the actual key value for security
			keysMetadata = append(keysMetadata, keyMetadata)
		}

		keysContent, err := json.Marshal(keysMetadata)
		if err == nil {
			npInput := jtypes.NPInput{
				Content: string(keysContent),
				Provenance: jtypes.NPProvenance{
					Platform:     "azure",
					ResourceType: "Microsoft.Storage/storageAccounts/keys",
					ResourceID:   fmt.Sprintf("%s/keys", resource.Key),
					AccountID:    subscriptionID,
				},
			}
			l.Send(npInput)
		}
	}

	return nil
}

func (l *AzureStorageSecretsLink) parseStorageResourceID(resourceID string) (resourceGroup, accountName string, err error) {
	parsed, err := helpers.ParseAzureResourceID(resourceID)
	if err != nil {
		return "", "", err
	}

	resourceGroup = parsed["resourceGroups"]
	accountName = parsed["storageAccounts"]

	if resourceGroup == "" || accountName == "" {
		return "", "", fmt.Errorf("invalid storage account resource ID format")
	}

	return resourceGroup, accountName, nil
}
