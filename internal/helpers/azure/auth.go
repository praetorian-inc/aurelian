package azure

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// NewAzureCredential returns an Azure token credential using the default
// credential chain (environment variables, managed identity, Azure CLI, etc.).
func NewAzureCredential() (azcore.TokenCredential, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}
	return cred, nil
}
