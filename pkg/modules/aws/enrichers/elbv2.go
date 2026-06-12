package enrichers

import (
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::ElasticLoadBalancingV2::LoadBalancer", enrichELBv2Wrapper)
}

func enrichELBv2Wrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	return EnrichELBv2LoadBalancer(cfg, r)
}

// EnrichELBv2LoadBalancer marks whether a load balancer is internet-facing.
// The Scheme property comes from CloudControl; this enricher normalizes it to a
// boolean for consistent downstream consumption.
func EnrichELBv2LoadBalancer(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	hydrateIfMissing(cfg, r, "Scheme")
	scheme, _ := r.Properties["Scheme"].(string)
	r.Properties["IsInternetFacing"] = strings.EqualFold(scheme, "internet-facing")
	return nil
}
