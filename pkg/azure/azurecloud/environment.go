// Package azurecloud resolves the two Azure deployments supported by Aurelian.
// Cloud selection belongs to a module/credential, never to process-global state.
package azurecloud

import (
	"fmt"
	"net/url"
	"strings"

	_ "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime" // register official ARM endpoints and audiences
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
)

const (
	Public     = "public"
	Government = "usgovernment"
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

// Resolve treats missing/empty legacy configuration as public. Explicit unknown
// values (including China and DoD/L5) must not fall back to public.
func Resolve(value string) (Environment, error) {
	var e Environment
	switch value {
	case "", Public:
		e = Environment{Name: Public, Cloud: cloud.AzurePublic, BlobSuffix: "blob.core.windows.net", CosmosSuffix: "documents.azure.com", AppConfigSuffix: "azconfig.io", AppServiceSuffix: "azurewebsites.net", TrafficManagerSuffix: "trafficmanager.net"}
	case Government:
		e = Environment{Name: Government, Cloud: cloud.AzureGovernment, BlobSuffix: "blob.core.usgovcloudapi.net", CosmosSuffix: "documents.azure.us", AppConfigSuffix: "azconfig.azure.us", AppServiceSuffix: "azurewebsites.us", TrafficManagerSuffix: "usgovtrafficmanager.net"}
	default:
		return Environment{}, fmt.Errorf("unsupported Azure cloud type %q: choose public or usgovernment", value)
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

// ValidateURL enforces an exact HTTPS origin, including pagination URLs. Do not
// include the raw URL in errors: queries can contain SAS/continuation tokens.
func ValidateURL(raw, origin string) error {
	u, err := url.Parse(raw)
	base, baseErr := url.Parse(origin)
	if err != nil || baseErr != nil || u.Scheme != "https" || !strings.EqualFold(strings.TrimSuffix(u.Host, ":443"), strings.TrimSuffix(base.Host, ":443")) || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("Azure request must remain on the selected HTTPS service origin")
	}
	return nil
}

// ValidateBlobURL validates a service-returned SAS URL in the selected cloud.
// Managed boot diagnostics may use a provider-owned account, so the exact account
// is supplied by ARM rather than inferred from the VM name. Redirects are disabled.
func ValidateBlobURL(raw string, environment Environment) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" && u.Port() != "443" || !strings.HasSuffix(strings.ToLower(u.Hostname()), "."+environment.BlobSuffix) {
		return fmt.Errorf("boot diagnostics URL must use the selected Azure Blob cloud")
	}
	name := strings.TrimSuffix(strings.ToLower(u.Hostname()), "."+environment.BlobSuffix)
	_, err = Endpoint(name, environment.BlobSuffix)
	return err
}

// Endpoint constructs only a single resource hostname, not an arbitrary URL.
func Endpoint(name, suffix string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("Azure resource name is empty")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return "", fmt.Errorf("invalid Azure resource hostname")
		}
	}
	return "https://" + name + "." + suffix, nil
}
