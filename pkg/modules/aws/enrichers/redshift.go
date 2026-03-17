package enrichers

import (
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::Redshift::Cluster", enrichRedshiftClusterWrapper)
}

func enrichRedshiftClusterWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	return EnrichRedshiftCluster(cfg, r)
}

// EnrichRedshiftCluster normalizes the PubliclyAccessible property from
// CloudControl into a consistent IsPubliclyAccessible boolean.
func EnrichRedshiftCluster(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	publiclyAccessible, _ := r.Properties["PubliclyAccessible"].(bool)
	r.Properties["IsPubliclyAccessible"] = publiclyAccessible
	return nil
}
