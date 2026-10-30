package auth

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
)

func NewAzureCredential(env azurecloud.Environment) (azcore.TokenCredential, error) {
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: env.ClientOptions()})
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}
	return cred, nil
}
