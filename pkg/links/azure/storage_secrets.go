package azure
import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)
// AzureStorageSecretsLink extracts secrets from Azure Storage Accounts
type AzureStorageSecretsLink struct {
	*base.NativeAzureLink
}
func NewAzureStorageSecretsLink(args map[string]any) *AzureStorageSecretsLink {
	return &AzureStorageSecretsLink{
		NativeAzureLink: base.NewNativeAzureLink("storage-secrets", args),
	}
}
func (l *AzureStorageSecretsLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		options.AzureSubscription(),
	}
}
func (l *AzureStorageSecretsLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource input, got %T", input)
	}
	subscriptionID := resource.AccountRef
	// Extract resource group and storage account name from resource ID
	resourceGroup, accountName, err := l.parseStorageResourceID(resource.ResourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse storage account resource ID: %w", err)
	}
	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}
	// Create storage accounts client
	client, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage accounts client: %w", err)
	}
	l.Logger().Debug("Scanning storage account keys",
		"resource_group", resourceGroup,
		"account_name", accountName)
	// Get storage account keys (requires appropriate permissions)
	keys, err := client.ListKeys(ctx, resourceGroup, accountName, nil)
	if err != nil {
		l.Logger().Error("Failed to get storage account keys", "error", err.Error())
		return l.Outputs(), nil // Don't fail the whole process
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
			npInput := types.NpInput{
				Content: string(keysContent),
				Provenance: types.NpProvenance{
					Platform:     "azure",
					ResourceType: "Microsoft.Storage/storageAccounts/keys",
					ResourceID:   fmt.Sprintf("%s/keys", resource.ResourceID),
					AccountID:    subscriptionID,
				},
			}
			l.Send(npInput)
		}
	}
	return l.Outputs(), nil
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
