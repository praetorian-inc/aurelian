package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/aws/ebtakeover"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&EBSubdomainTakeoverModule{})
}

// EBSubdomainTakeoverConfig holds the typed parameters for the eb-subdomain-takeover module.
type EBSubdomainTakeoverConfig struct {
	plugin.AWSCommonRecon
}

// EBSubdomainTakeoverModule detects dangling Route53 CNAME records pointing
// to terminated Elastic Beanstalk environments that are vulnerable to subdomain takeover.
type EBSubdomainTakeoverModule struct {
	EBSubdomainTakeoverConfig
}

func (m *EBSubdomainTakeoverModule) ID() string                { return "eb-subdomain-takeover" }
func (m *EBSubdomainTakeoverModule) Name() string              { return "AWS Elastic Beanstalk Subdomain Takeover" }
func (m *EBSubdomainTakeoverModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *EBSubdomainTakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *EBSubdomainTakeoverModule) OpsecLevel() string        { return "safe" }
func (m *EBSubdomainTakeoverModule) Authors() []string         { return []string{"Praetorian"} }

func (m *EBSubdomainTakeoverModule) Description() string {
	return "Detects dangling Route53 CNAME records pointing to terminated Elastic Beanstalk " +
		"environments. Enumerates public hosted zones, matches CNAME records against the " +
		"elasticbeanstalk.com pattern, and validates each prefix with the " +
		"elasticbeanstalk:CheckDNSAvailability API. Returns High-severity findings for each " +
		"unclaimed prefix that is vulnerable to subdomain takeover."
}

func (m *EBSubdomainTakeoverModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CheckDNSAvailability.html",
		"https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-heroku-github-desk-more/",
		"https://hackerone.com/reports/473888",
	}
}

func (m *EBSubdomainTakeoverModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::Route53::RecordSet",
	}
}

func (m *EBSubdomainTakeoverModule) Parameters() any {
	return &m.EBSubdomainTakeoverConfig
}

func (m *EBSubdomainTakeoverModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.EBSubdomainTakeoverConfig

	resolvedRegions, err := resolveRegions(c.Regions, c.Profile, c.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve regions: %w", err)
	}

	opts := ebtakeover.ScanOptions{
		Profile:     c.Profile,
		ProfileDir:  c.ProfileDir,
		Regions:     resolvedRegions,
		Concurrency: c.Concurrency,
	}

	risks, err := ebtakeover.Scan(opts)
	if err != nil {
		return nil, err
	}

	return []plugin.Result{
		{
			Data: risks,
			Metadata: map[string]any{
				"module":   m.ID(),
				"platform": m.Platform(),
				"regions":  resolvedRegions,
			},
		},
	}, nil
}
