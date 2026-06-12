package enrichers

import (
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::OpenSearchService::Domain", enrichOpenSearchWrapper)
	plugin.RegisterEnricher("AWS::Elasticsearch::Domain", enrichOpenSearchWrapper)
}

func enrichOpenSearchWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	return EnrichOpenSearchDomain(cfg, r)
}

// EnrichOpenSearchDomain flattens whether fine-grained access control is
// enabled (AdvancedSecurityOptions.Enabled, a nested map from CloudControl).
// When FGAC is disabled, the access policy is the only authorization layer.
func EnrichOpenSearchDomain(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	fgacEnabled := false
	if aso, ok := r.Properties["AdvancedSecurityOptions"].(map[string]any); ok {
		fgacEnabled, _ = aso["Enabled"].(bool)
	}
	r.Properties["FGACEnabled"] = fgacEnabled
	return nil
}
