package recon

import (
	"fmt"
	"slices"

	"github.com/praetorian-inc/aurelian/pkg/aws/enrichment"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSConfigurationScanModule{})
}

type ConfigurationScanConfig struct {
	plugin.AWSCommonRecon
}

// AWSConfigurationScanModule enumerates AWS resources once, runs the shared
// enrichers, then fans each enriched resource through resource-posture Checks
// that emit risks. IMDSv1 is the first check.
type AWSConfigurationScanModule struct {
	ConfigurationScanConfig
	checks []Check
}

func (m *AWSConfigurationScanModule) ID() string                { return "configuration-scan" }
func (m *AWSConfigurationScanModule) Name() string              { return "AWS Configuration Scan" }
func (m *AWSConfigurationScanModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSConfigurationScanModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSConfigurationScanModule) OpsecLevel() string        { return "moderate" }
func (m *AWSConfigurationScanModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSConfigurationScanModule) Description() string {
	return "Evaluates AWS resource configuration posture and emits risks. " +
		"Enumerates supported resource types once, enriches them, and runs typed checks " +
		"(currently: EC2 IMDSv1 enabled)."
}

func (m *AWSConfigurationScanModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
	}
}

func (m *AWSConfigurationScanModule) SupportedResourceTypes() []string {
	types := map[string]struct{}{}
	for _, c := range m.activeChecks() {
		types[c.ResourceType()] = struct{}{}
	}
	// Deterministic order; today this is exactly ["AWS::EC2::Instance"].
	out := make([]string, 0, len(types))
	for t := range types {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

func (m *AWSConfigurationScanModule) Parameters() any { return &m.ConfigurationScanConfig }

func (m *AWSConfigurationScanModule) activeChecks() []Check {
	if m.checks == nil {
		return defaultChecks()
	}
	return m.checks
}

func (m *AWSConfigurationScanModule) runChecks(r output.AWSResource, out *pipeline.P[model.AurelianModel]) error {
	for _, c := range m.activeChecks() {
		if c.ResourceType() != r.ResourceType {
			continue
		}
		if risk := c.Evaluate(r); risk != nil {
			out.Send(*risk)
		}
	}
	return nil
}

func (m *AWSConfigurationScanModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.ConfigurationScanConfig

	lister := cclist.NewEnumerator(c.AWSCommonRecon)
	defer func() { _ = lister.Close() }()

	inputs, err := collectInputs(m.AWSCommonRecon, m.SupportedResourceTypes())
	if err != nil {
		return fmt.Errorf("failed to collect inputs: %w", err)
	}
	cfg.Info("configuration scan: %d input(s) across %d region(s)", len(inputs), len(c.Regions))

	inputPipeline := pipeline.From(inputs...)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(inputPipeline, lister.List, listed, &pipeline.PipeOpts{
		Progress: cfg.Log.ProgressFunc("listing resources"),
	})

	enricher := enrichment.NewAWSEnricher(c.AWSCommonRecon)
	enriched := pipeline.New[output.AWSResource]()
	pipeline.Pipe(listed, enricher.Enrich, enriched, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("enriching resources"),
		Concurrency: c.Concurrency,
	})

	pipeline.Pipe(enriched, m.runChecks, out)

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("configuration scan complete")
	return nil
}
