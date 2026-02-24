package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/aws/eiptakeover"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&EIPDanglingTakeoverModule{})
}

// EIPDanglingTakeoverConfig holds the typed parameters for the eip-dangling-takeover module.
type EIPDanglingTakeoverConfig struct {
	plugin.AWSCommonRecon
}

// EIPDanglingTakeoverModule detects Route53 A records pointing to AWS IPs
// that are not allocated as Elastic IPs in this account.
type EIPDanglingTakeoverModule struct {
	EIPDanglingTakeoverConfig
}

func (m *EIPDanglingTakeoverModule) ID() string                { return "eip-dangling-takeover" }
func (m *EIPDanglingTakeoverModule) Name() string              { return "AWS EC2 Elastic IP Dangling A Record Takeover" }
func (m *EIPDanglingTakeoverModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *EIPDanglingTakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *EIPDanglingTakeoverModule) OpsecLevel() string        { return "safe" }
func (m *EIPDanglingTakeoverModule) Authors() []string         { return []string{"Praetorian"} }
func (m *EIPDanglingTakeoverModule) Parameters() any           { return &m.EIPDanglingTakeoverConfig }

func (m *EIPDanglingTakeoverModule) Description() string {
	return "Detects Route53 A records pointing to AWS IP addresses that are not allocated as Elastic IPs in this account. Such dangling records can be taken over by an attacker who allocates the released IP."
}

func (m *EIPDanglingTakeoverModule) References() []string {
	return []string{
		"https://bishopfox.com/blog/fishing-the-aws-ip-pool-for-dangling-domains",
		"https://github.com/assetnote/ghostbuster",
		"https://kmsec.uk/blog/passive-takeover/",
	}
}

func (m *EIPDanglingTakeoverModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::Route53::RecordSet",
		"AWS::EC2::EIP",
	}
}

func (m *EIPDanglingTakeoverModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.EIPDanglingTakeoverConfig

	resolvedRegions, err := resolveRegions(c.Regions, c.Profile, c.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve regions: %w", err)
	}

	opts := eiptakeover.ScanOptions{
		Profile:     c.Profile,
		ProfileDir:  c.ProfileDir,
		Regions:     resolvedRegions,
		Concurrency: c.Concurrency,
	}

	risks, err := eiptakeover.Scan(opts)
	if err != nil {
		return nil, fmt.Errorf("eip dangling takeover scan failed: %w", err)
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
