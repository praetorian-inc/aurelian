package enrichers

import (
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::RDS::DBInstance", enrichRDSInstanceWrapper)
}

func enrichRDSInstanceWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	return EnrichRDSInstance(cfg, r)
}

// EnrichRDSInstance marks whether an RDS instance is publicly accessible.
// The PubliclyAccessible property comes from CloudControl; this enricher
// normalizes it to a boolean for consistent downstream consumption.
func EnrichRDSInstance(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	publiclyAccessible, _ := r.Properties["PubliclyAccessible"].(bool)
	r.Properties["IsPubliclyAccessible"] = publiclyAccessible
	return nil
}
