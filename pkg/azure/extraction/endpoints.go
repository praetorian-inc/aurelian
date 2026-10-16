package extraction

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// resourceEndpoint prefers the ARM/ARG-returned endpoint, but only when it is
// the expected account/store origin in the credential's cloud. Legacy resources
// without endpoint properties use the documented service suffix. Custom/private
// or DNS-zone endpoints need separate validation and must not receive credentials
// by falling back silently to a different host.
func resourceEndpoint(resource output.AzureResource, name, suffix string, propertyPath ...string) (string, error) {
	expected, err := azurecloud.Endpoint(name, suffix)
	if err != nil {
		return "", err
	}
	var property any = resource.Properties
	for _, key := range propertyPath {
		object, ok := property.(map[string]any)
		if !ok {
			if property == nil {
				return expected, nil
			}
			return "", fmt.Errorf("Azure service endpoint property has an unexpected type")
		}
		property = object[key]
	}
	if property == nil {
		return expected, nil
	}
	raw, ok := property.(string)
	if !ok || raw == "" {
		return "", fmt.Errorf("Azure service endpoint property is invalid")
	}
	endpoint, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("Azure service endpoint is invalid")
	}
	// ARM Cosmos endpoints commonly spell out the standard HTTPS port.
	if endpoint.Scheme == "https" && endpoint.Port() == "443" {
		endpoint.Host = endpoint.Hostname()
	}
	if err := azurecloud.ValidateURL(endpoint.String(), expected); err != nil {
		return "", err
	}
	if endpoint.Path != "" && endpoint.Path != "/" || endpoint.RawQuery != "" {
		return "", fmt.Errorf("Azure service endpoint must not contain a path or query")
	}
	return strings.TrimSuffix(endpoint.String(), "/"), nil
}
