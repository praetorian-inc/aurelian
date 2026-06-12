package enrichers

import (
	"slices"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::EKS::Cluster", enrichEKSWrapper)
}

func enrichEKSWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	return EnrichEKSCluster(cfg, r)
}

// EnrichEKSCluster flattens ResourcesVpcConfig (a nested map from CloudControl)
// into whether the Kubernetes API server endpoint is publicly accessible and
// whether public access is open to the entire internet (0.0.0.0/0).
func EnrichEKSCluster(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	hydrateIfMissing(cfg, r, "ResourcesVpcConfig", "EndpointPublicAccess")
	publicAccess := false
	openToInternet := false
	if vpc, ok := r.Properties["ResourcesVpcConfig"].(map[string]any); ok {
		publicAccess, _ = vpc["EndpointPublicAccess"].(bool)
		openToInternet = cidrsContainAllIPv4(vpc["PublicAccessCidrs"])
	}
	r.Properties["EndpointPublicAccess"] = publicAccess
	r.Properties["PublicAccessOpenToInternet"] = openToInternet
	return nil
}

func cidrsContainAllIPv4(raw any) bool {
	cidrs, ok := raw.([]any)
	if !ok {
		return false
	}
	return slices.ContainsFunc(cidrs, func(c any) bool {
		s, ok := c.(string)
		return ok && (s == "0.0.0.0/0" || s == "::/0")
	})
}
