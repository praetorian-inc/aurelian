package auth

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func NewAzureCredential() (azcore.TokenCredential, error) {
	// If service principal environment variables are set, use them directly.
	if os.Getenv("AZURE_CLIENT_ID") != "" && os.Getenv("AZURE_TENANT_ID") != "" {
		slog.Info("using DefaultAzureCredential (service principal env vars detected)")
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure credential: %w", err)
		}
		return cred, nil
	}

	// Otherwise prefer AzureCLI credential directly — DefaultAzureCredential
	// probes IMDS and other credential sources that can stall on non-Azure
	// machines due to HTTP/2 connection issues with login.microsoftonline.com.
	slog.Info("attempting AzureCLI credential")
	cred, err := azidentity.NewAzureCLICredential(nil)
	if err != nil {
		slog.Warn("AzureCLI credential failed, falling back to DefaultAzureCredential", "error", err)
		defCred, defErr := azidentity.NewDefaultAzureCredential(nil)
		if defErr != nil {
			return nil, fmt.Errorf("failed to create Azure credential: %w (CLI: %w)", defErr, err)
		}
		return defCred, nil
	}
	slog.Info("using AzureCLI credential")
	return cred, nil
}
