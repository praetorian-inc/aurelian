// Package azurecloud resolves the two Azure deployments supported by Aurelian.
// Cloud selection belongs to a module/credential, never to process-global state.
package azurecloud

import (
	"slices"

	_ "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime" // register official ARM endpoints and audiences
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
)

const (
	Public     = "public"
	Government = "gcc-high"
)

type Environment struct {
	Name                 string
	Cloud                cloud.Configuration
	AppConfigAudience    string // "" lets azappconfig derive the scope from the store endpoint
	BlobSuffix           string
	CosmosSuffix         string
	AppConfigSuffix      string
	AppServiceSuffix     string
	TrafficManagerSuffix string
}

// Resolve maps a cloud-type flag to its Environment; anything other than
// Government (including empty/legacy values) is Public.
func Resolve(value string) Environment {
	if value == Government {
		return Environment{Name: Government, Cloud: cloud.AzureGovernment, AppConfigAudience: "https://appconfig.azure.us", BlobSuffix: "blob.core.usgovcloudapi.net", CosmosSuffix: "documents.azure.us", AppConfigSuffix: "azconfig.azure.us", AppServiceSuffix: "azurewebsites.us", TrafficManagerSuffix: "usgovtrafficmanager.net"}
	}
	return Environment{Name: Public, Cloud: cloud.AzurePublic, BlobSuffix: "blob.core.windows.net", CosmosSuffix: "documents.azure.com", AppConfigSuffix: "azconfig.io", AppServiceSuffix: "azurewebsites.net", TrafficManagerSuffix: "trafficmanager.net"}
}

func (e Environment) ARMEndpoint() string {
	return e.Cloud.Services[cloud.ResourceManager].Endpoint
}

// ARMScope mirrors azcore/arm/runtime so raw-HTTP callers request the same scope as SDK clients.
func (e Environment) ARMScope() string {
	return e.Cloud.Services[cloud.ResourceManager].Audience + "/.default"
}

// Supports reports whether a capability registered for clouds runs here; nil means every cloud.
func (e Environment) Supports(clouds []string) bool {
	return len(clouds) == 0 || slices.Contains(clouds, e.Name)
}
