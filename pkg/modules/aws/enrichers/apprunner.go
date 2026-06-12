package enrichers

import (
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::AppRunner::Service", enrichAppRunnerWrapper)
}

func enrichAppRunnerWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	return EnrichAppRunnerService(cfg, r)
}

// EnrichAppRunnerService marks whether an App Runner service accepts public
// ingress. NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible comes
// from CloudControl as nested maps; this enricher normalizes it to a top-level
// boolean and surfaces the service URL for downstream consumption.
func EnrichAppRunnerService(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	hydrateIfMissing(cfg, r, "NetworkConfiguration", "IngressConfiguration", "IsPubliclyAccessible")
	publiclyAccessible := false
	if nc, ok := r.Properties["NetworkConfiguration"].(map[string]any); ok {
		if ic, ok := nc["IngressConfiguration"].(map[string]any); ok {
			publiclyAccessible, _ = ic["IsPubliclyAccessible"].(bool)
		}
	}
	r.Properties["IsPubliclyAccessible"] = publiclyAccessible
	return nil
}
