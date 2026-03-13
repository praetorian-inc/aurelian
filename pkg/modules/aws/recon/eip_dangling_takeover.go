package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/aws/eiptakeover"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
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
	return nil
}

func (m *EIPDanglingTakeoverModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.EIPDanglingTakeoverConfig

	opts := eiptakeover.ScanOptions{
		Profile:     c.Profile,
		ProfileDir:  c.ProfileDir,
		Regions:     c.Regions,
		Concurrency: c.Concurrency,
	}

	var count int
	err := eiptakeover.Scan(opts, func(risk output.AurelianRisk) {
		count++
		out.Send(risk)
	})
	if err != nil {
		return fmt.Errorf("eip dangling takeover scan: %w", err)
	}

	cfg.Info("found %d dangling records", count)
	return nil
}
