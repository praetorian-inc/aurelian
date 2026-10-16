package auth

import (
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
)

func NewAzureCredential() (azcore.TokenCredential, error) {
	return NewAzureCredentialForCloud("")
}

func NewAzureCredentialForCloud(cloudType string) (azcore.TokenCredential, error) {
	environment, err := azurecloud.Resolve(cloudType)
	if err != nil {
		return nil, err
	}
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: azcore.ClientOptions{Cloud: environment.Cloud, Transport: http.DefaultClient}})
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}
	return azurecloud.WithCloud(cred, cloudType)
}
