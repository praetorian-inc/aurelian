package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/aws/nstakeover"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&NSDelegationTakeoverModule{})
}

// NSDelegationTakeoverConfig holds the typed parameters for the ns-delegation-takeover module.
type NSDelegationTakeoverConfig struct {
	plugin.AWSCommonRecon
}

// NSDelegationTakeoverModule detects dangling Route53 NS delegation records
// pointing to orphaned hosted zones that are vulnerable to DNS takeover via
// the Form3 bypass technique.
type NSDelegationTakeoverModule struct {
	NSDelegationTakeoverConfig
}

func (m *NSDelegationTakeoverModule) ID() string                { return "ns-delegation-takeover" }
func (m *NSDelegationTakeoverModule) Name() string              { return "AWS Route53 NS Delegation Takeover" }
func (m *NSDelegationTakeoverModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *NSDelegationTakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *NSDelegationTakeoverModule) OpsecLevel() string        { return "safe" }
func (m *NSDelegationTakeoverModule) Authors() []string         { return []string{"Praetorian"} }
func (m *NSDelegationTakeoverModule) Parameters() any           { return &m.NSDelegationTakeoverConfig }

func (m *NSDelegationTakeoverModule) Description() string {
	return "Detects dangling Route53 NS delegation records pointing to orphaned hosted zones. " +
		"Enumerates public hosted zones, finds NS records that delegate to Route53 nameservers " +
		"(ns-*.awsdns-*), and validates each delegation by querying the nameserver directly. " +
		"When a nameserver returns SERVFAIL, REFUSED, or NXDOMAIN, the hosted zone has been " +
		"deleted and an attacker can exploit the Form3 bypass to create a new hosted zone and " +
		"gain full DNS control over the delegated subdomain."
}

func (m *NSDelegationTakeoverModule) References() []string {
	return []string{
		"https://www.form3.tech/blog/engineering/dangling-danger",
		"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
		"https://0xpatrik.com/subdomain-takeover-ns/",
	}
}

func (m *NSDelegationTakeoverModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::Route53::RecordSet",
	}
}

func (m *NSDelegationTakeoverModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.NSDelegationTakeoverConfig

	opts := nstakeover.ScanOptions{
		Profile:     c.Profile,
		ProfileDir:  c.ProfileDir,
		Concurrency: c.Concurrency,
	}

	risks, err := nstakeover.Scan(opts)
	if err != nil {
		return nil, fmt.Errorf("ns delegation takeover scan failed: %w", err)
	}

	return []plugin.Result{
		{
			Data: risks,
			Metadata: map[string]any{
				"module":   m.ID(),
				"platform": m.Platform(),
			},
		},
	}, nil
}
