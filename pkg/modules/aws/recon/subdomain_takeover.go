package recon

import (
	"github.com/praetorian-inc/aurelian/pkg/aws/dnstakeover"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&SubdomainTakeoverModule{})
}

type SubdomainTakeoverConfig struct {
	plugin.AWSCommonRecon
}

type SubdomainTakeoverModule struct {
	SubdomainTakeoverConfig
}

func (m *SubdomainTakeoverModule) ID() string                { return "subdomain-takeover" }
func (m *SubdomainTakeoverModule) Name() string              { return "AWS Subdomain Takeover" }
func (m *SubdomainTakeoverModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *SubdomainTakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *SubdomainTakeoverModule) OpsecLevel() string        { return "safe" }
func (m *SubdomainTakeoverModule) Authors() []string         { return []string{"Praetorian"} }
func (m *SubdomainTakeoverModule) Parameters() any           { return &m.SubdomainTakeoverConfig }

func (m *SubdomainTakeoverModule) Description() string {
	return "Detects dangling DNS records in Route53 that are vulnerable to subdomain takeover. " +
		"Enumerates all records from public hosted zones and checks for: Elastic Beanstalk " +
		"CNAME hijacking, dangling Elastic IP A records, and orphaned NS delegations."
}

func (m *SubdomainTakeoverModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CheckDNSAvailability.html",
		"https://www.form3.tech/blog/engineering/dangling-danger",
		"https://bishopfox.com/blog/fishing-the-aws-ip-pool-for-dangling-domains",
	}
}

func (m *SubdomainTakeoverModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::Route53::HostedZone",
	}
}

func (m *SubdomainTakeoverModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	checker, err := dnstakeover.NewDNSTakeoverChecker(m.AWSCommonRecon)
	if err != nil {
		return err
	}

	cfg.Info("enumerating Route53 records from public hosted zones")

	enumerator := dnstakeover.NewRoute53Enumerator(m.AWSCommonRecon)
	trigger := pipeline.From("route53")

	records := pipeline.New[dnstakeover.Route53Record]()
	pipeline.Pipe(trigger, enumerator.EnumerateAll, records, &pipeline.PipeOpts{
		Progress: cfg.Log.ProgressFunc("enumerating route53 records"),
	})

	pipeline.Pipe(records, checker.Check, out, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("checking for takeover"),
		Concurrency: m.Concurrency,
	})

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("subdomain takeover scan complete")
	return nil
}
