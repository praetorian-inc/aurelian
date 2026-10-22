package azurecloud

import (
	"slices"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
)

const (
	Public     = "public"
	Government = "gcc-high"
)

type Environment struct {
	Name                 string
	Cloud                cloud.Configuration
	AppConfigAudience    string // Empty preserves the SDK's store-specific audience.
	BlobSuffix           string
	AppServiceSuffix     string
	TrafficManagerSuffix string
}

// Resolve selects Government only for "gcc-high"; all other values remain Public.
func Resolve(value string) Environment {
	if value == Government {
		return Environment{
			Name: Government, Cloud: cloud.AzureGovernment,
			AppConfigAudience:    "https://appconfig.azure.us",
			BlobSuffix:           ".blob.core.usgovcloudapi.net",
			AppServiceSuffix:     ".azurewebsites.us",
			TrafficManagerSuffix: ".usgovtrafficmanager.net",
		}
	}
	return Environment{
		Name: Public, Cloud: cloud.AzurePublic,
		BlobSuffix:           ".blob.core.windows.net",
		AppServiceSuffix:     ".azurewebsites.net",
		TrafficManagerSuffix: ".trafficmanager.net",
	}
}

// Supports reports whether a capability is registered for this cloud.
// An empty list means all clouds.
func (e Environment) Supports(clouds []string) bool {
	return len(clouds) == 0 || slices.Contains(clouds, e.Name)
}

func (e Environment) ARMClientOptions() *arm.ClientOptions {
	return &arm.ClientOptions{ClientOptions: e.ClientOptions()}
}

func (e Environment) ClientOptions() azcore.ClientOptions {
	// A zero Cloud retains the SDK's fail-open default to Azure Public.
	return azcore.ClientOptions{Cloud: e.Cloud}
}
