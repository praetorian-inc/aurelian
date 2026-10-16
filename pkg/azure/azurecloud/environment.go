// Package azurecloud resolves the two Azure deployments supported by Aurelian.
// Cloud selection belongs to a module/credential, never to process-global state.
package azurecloud

import (
	"fmt"
	"strings"

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
	ARM                  string
	ARMScope             string
	BlobSuffix           string
	CosmosSuffix         string
	AppConfigSuffix      string
	AppServiceSuffix     string
	TrafficManagerSuffix string
}

// Resolve treats missing/empty legacy configuration as public.
func Resolve(value string) (Environment, error) {
	var e Environment
	switch value {
	case "", Public:
		e = Environment{Name: Public, Cloud: cloud.AzurePublic, BlobSuffix: "blob.core.windows.net", CosmosSuffix: "documents.azure.com", AppConfigSuffix: "azconfig.io", AppServiceSuffix: "azurewebsites.net", TrafficManagerSuffix: "trafficmanager.net"}
	case Government:
		e = Environment{Name: Government, Cloud: cloud.AzureGovernment, BlobSuffix: "blob.core.usgovcloudapi.net", CosmosSuffix: "documents.azure.us", AppConfigSuffix: "azconfig.azure.us", AppServiceSuffix: "azurewebsites.us", TrafficManagerSuffix: "usgovtrafficmanager.net"}
	default:
		return Environment{}, fmt.Errorf("unsupported Azure cloud type %q: choose public or gcc-high", value)
	}
	// Copy SDK metadata: callers must not mutate SDK-global maps or another job.
	services := make(map[cloud.ServiceName]cloud.ServiceConfiguration, len(e.Cloud.Services))
	for name, service := range e.Cloud.Services {
		// azcore ARM appends "/.default" without trimming the SDK metadata's
		// trailing slash. Normalize our private copy, not the global SDK map.
		service.Audience = strings.TrimRight(service.Audience, "/")
		services[name] = service
	}
	e.Cloud.Services = services
	arm := services[cloud.ResourceManager]
	e.ARM = arm.Endpoint
	e.ARMScope = strings.TrimRight(arm.Audience, "/") + "/.default"
	return e, nil
}
