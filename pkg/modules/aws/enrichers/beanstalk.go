package enrichers

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::ElasticBeanstalk::Environment", enrichBeanstalkWrapper)
}

// BeanstalkClient is the subset of the elasticbeanstalk API used for enrichment.
type BeanstalkClient interface {
	DescribeConfigurationSettings(ctx context.Context, params *elasticbeanstalk.DescribeConfigurationSettingsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeConfigurationSettingsOutput, error)
}

// enrichBeanstalkWrapper hydrates the environment's full property set
// (CloudControl ListResources returns only EnvironmentName), rewrites the ARN
// (environment/<ApplicationName>/<EnvironmentName> — ApplicationName is only
// available after hydration), then resolves the fronting load balancer scheme.
func enrichBeanstalkWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	hydrateFromCloudControl(cfg, r)

	app, _ := r.Properties["ApplicationName"].(string)
	env, _ := r.Properties["EnvironmentName"].(string)
	if app != "" && env != "" && r.Region != "" && r.AccountRef != "" {
		r.ARN = fmt.Sprintf("arn:aws:elasticbeanstalk:%s:%s:environment/%s/%s",
			r.Region, r.AccountRef, app, env)
	}

	client := elasticbeanstalk.NewFromConfig(cfg.AWSConfig)
	return EnrichBeanstalkEnvironment(cfg, r, client)
}

// EnrichBeanstalkEnvironment marks whether the environment's fronting load
// balancer is internal. A load-balanced environment with ELBScheme=internal is
// reachable only from within the VPC despite still exposing an endpoint/CNAME,
// so the evaluator must not flag it as internet-facing. Single-instance and
// public-LB environments leave IsInternalLB=false and the evaluator treats them
// as internet-facing.
func EnrichBeanstalkEnvironment(cfg plugin.EnricherConfig, r *output.AWSResource, client BeanstalkClient) error {
	app, _ := r.Properties["ApplicationName"].(string)
	env, _ := r.Properties["EnvironmentName"].(string)
	if app == "" || env == "" {
		return nil
	}

	out, err := client.DescribeConfigurationSettings(cfg.Context, &elasticbeanstalk.DescribeConfigurationSettingsInput{
		ApplicationName: &app,
		EnvironmentName: &env,
	})
	if err != nil {
		// Best-effort: without the scheme the evaluator falls back to flagging
		// (conservative). Surface the error so the pipeline logs it.
		return fmt.Errorf("describe Beanstalk config for %s/%s: %w", app, env, err)
	}

	envType, elbScheme := "", ""
	for _, cs := range out.ConfigurationSettings {
		for _, o := range cs.OptionSettings {
			switch {
			case aws.ToString(o.Namespace) == "aws:elasticbeanstalk:environment" && aws.ToString(o.OptionName) == "EnvironmentType":
				envType = aws.ToString(o.Value)
			case aws.ToString(o.Namespace) == "aws:ec2:vpc" && aws.ToString(o.OptionName) == "ELBScheme":
				elbScheme = aws.ToString(o.Value)
			}
		}
	}
	r.Properties["IsInternalLB"] = envType == "LoadBalanced" && strings.EqualFold(elbScheme, "internal")
	return nil
}
