package enrichers

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::ElasticBeanstalk::Environment", enrichBeanstalk)
}

// enrichBeanstalk hydrates the environment's full property set (CloudControl
// ListResources returns only EnvironmentName) and rewrites the ARN. An Elastic
// Beanstalk environment ARN is environment/<ApplicationName>/<EnvironmentName> —
// the application name is only available after hydration, so the synthesized
// ARN from enumeration (which has just the environment name) cannot be correct
// until now.
func enrichBeanstalk(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	hydrateFromCloudControl(cfg, r)

	app, _ := r.Properties["ApplicationName"].(string)
	env, _ := r.Properties["EnvironmentName"].(string)
	if app != "" && env != "" && r.Region != "" && r.AccountRef != "" {
		r.ARN = fmt.Sprintf("arn:aws:elasticbeanstalk:%s:%s:environment/%s/%s",
			r.Region, r.AccountRef, app, env)
	}
	return nil
}
