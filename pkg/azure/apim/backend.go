package apim

import (
	"net/url"
	"strings"
)

// BackendCategory labels an APIM backend's target hostname by the kind of
// infrastructure it appears to run on. Used to decide whether Aurelian can
// determine direct reachability from Azure APIs alone, or whether the
// backend must be flagged for manual verification.
type BackendCategory string

const (
	BackendAppService            BackendCategory = "azure-app-service"
	BackendAppServiceEnvironment BackendCategory = "azure-app-service-environment"
	BackendAPIM                  BackendCategory = "azure-apim"
	BackendGCPCloudRun           BackendCategory = "gcp-cloud-run"
	BackendOpenShift             BackendCategory = "openshift"
	BackendOther                 BackendCategory = "other"
)

// CategorizeBackendURL parses an APIM backend URL and classifies its target
// by hostname suffix. The returned FQDN is lower-cased and has any port
// stripped; it is empty when the URL cannot be parsed.
func CategorizeBackendURL(rawURL string) (BackendCategory, string) {
	host := extractHost(rawURL)
	if host == "" {
		return BackendOther, ""
	}

	switch {
	case strings.HasSuffix(host, ".appserviceenvironment.net"):
		return BackendAppServiceEnvironment, host
	case strings.HasSuffix(host, ".azurewebsites.net"):
		return BackendAppService, host
	case strings.HasSuffix(host, ".azure-api.net"):
		return BackendAPIM, host
	case strings.HasSuffix(host, ".a.run.app") || strings.HasSuffix(host, ".run.app"):
		return BackendGCPCloudRun, host
	case openShiftRoutePattern(host):
		return BackendOpenShift, host
	default:
		return BackendOther, host
	}
}

// openShiftRoutePattern detects the default-route shape of an OpenShift
// application: "<app>.apps.<cluster-domain>". This covers ARO clusters like
// "apps.arocorpitdev.az.micron.com".
func openShiftRoutePattern(host string) bool {
	return strings.Contains(host, ".apps.")
}

func extractHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
