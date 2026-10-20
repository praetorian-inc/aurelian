// Package azurecloud resolves the two Azure deployments supported by Aurelian.
// Cloud selection belongs to a module/credential, never to process-global state.
package azurecloud

import (
	"fmt"
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

// Resolve treats missing/empty legacy configuration as public.
func Resolve(value string) (Environment, error) {
	switch value {
	case "", Public:
		return Environment{Name: Public, Cloud: cloud.AzurePublic, BlobSuffix: "blob.core.windows.net", CosmosSuffix: "documents.azure.com", AppConfigSuffix: "azconfig.io", AppServiceSuffix: "azurewebsites.net", TrafficManagerSuffix: "trafficmanager.net"}, nil
	case Government:
		return Environment{Name: Government, Cloud: cloud.AzureGovernment, AppConfigAudience: "https://appconfig.azure.us", BlobSuffix: "blob.core.usgovcloudapi.net", CosmosSuffix: "documents.azure.us", AppConfigSuffix: "azconfig.azure.us", AppServiceSuffix: "azurewebsites.us", TrafficManagerSuffix: "usgovtrafficmanager.net"}, nil
	default:
		return Environment{}, fmt.Errorf("unsupported Azure cloud type %q: choose public or gcc-high", value)
	}
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
