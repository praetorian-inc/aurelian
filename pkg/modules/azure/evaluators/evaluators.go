package evaluators

import (
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEvaluator("app_service_auth_disabled", func(r templates.ARGQueryResult) bool {
		v, ok := r.Properties["authEnabled"].(bool)
		return ok && !v
	})

	plugin.RegisterAzureEvaluator("app_service_remote_debugging_enabled", func(r templates.ARGQueryResult) bool {
		v, ok := r.Properties["remoteDebuggingEnabled"].(bool)
		return ok && v
	})

	plugin.RegisterAzureEvaluator("databases_allow_azure_services", func(r templates.ARGQueryResult) bool {
		v, ok := r.Properties["allowAzureServicesFirewall"].(bool)
		return ok && v
	})

	plugin.RegisterAzureEvaluator("function_app_http_anonymous_access", func(r templates.ARGQueryResult) bool {
		v, ok := r.Properties["hasAnonymousHttpTrigger"].(bool)
		return ok && v
	})

	plugin.RegisterAzureEvaluator("vm_privileged_managed_identity", func(r templates.ARGQueryResult) bool {
		v, ok := r.Properties["hasPrivilegedManagedIdentity"].(bool)
		return ok && v
	})
}
