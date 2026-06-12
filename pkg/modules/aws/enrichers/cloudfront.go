package enrichers

import (
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::CloudFront::Distribution", enrichCloudFrontWrapper)
}

func enrichCloudFrontWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	return EnrichCloudFrontDistribution(cfg, r)
}

// EnrichCloudFrontDistribution flattens DistributionConfig (returned by
// CloudControl as a nested map) into top-level booleans: whether the
// distribution is enabled and whether a WAF web ACL is attached.
func EnrichCloudFrontDistribution(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	hydrateIfMissing(cfg, r, "DistributionConfig", "Enabled")
	enabled := false
	hasWebACL := false
	if dc, ok := r.Properties["DistributionConfig"].(map[string]any); ok {
		enabled, _ = dc["Enabled"].(bool)
		if webACL, ok := dc["WebACLId"].(string); ok && webACL != "" {
			hasWebACL = true
		}
	}
	r.Properties["DistributionEnabled"] = enabled
	r.Properties["HasWebACL"] = hasWebACL
	return nil
}
