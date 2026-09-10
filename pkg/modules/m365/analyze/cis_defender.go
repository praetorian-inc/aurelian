package analyze

import (
	"context"
	"fmt"
	"log/slog"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"

	"github.com/praetorian-inc/aurelian/pkg/m365/collectors"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	m365templates "github.com/praetorian-inc/aurelian/pkg/templates/m365"
	cisdefender "github.com/praetorian-inc/aurelian/pkg/templates/m365/cis-defender"
)

func init() {
	plugin.Register(&M365DefenderCISModule{})
}

type M365DefenderCISConfig struct {
	plugin.M365CommonParams
}

type M365DefenderCISModule struct {
	M365DefenderCISConfig
}

func (m *M365DefenderCISModule) ID() string                      { return "cis-defender" }
func (m *M365DefenderCISModule) Name() string                    { return "M365 CIS Defender Benchmark" }
func (m *M365DefenderCISModule) Platform() plugin.Platform       { return plugin.PlatformM365 }
func (m *M365DefenderCISModule) Category() plugin.Category       { return plugin.CategoryAnalyze }
func (m *M365DefenderCISModule) OpsecLevel() string              { return "safe" }
func (m *M365DefenderCISModule) Authors() []string               { return []string{"Praetorian"} }
func (m *M365DefenderCISModule) SupportedResourceTypes() []string { return []string{"m365tenant"} }
func (m *M365DefenderCISModule) Parameters() any                 { return &m.M365DefenderCISConfig }

func (m *M365DefenderCISModule) Description() string {
	return "Evaluates Microsoft 365 Defender (Section 2) against CIS Benchmark v6.0 controls"
}

func (m *M365DefenderCISModule) References() []string {
	return []string{"https://www.cisecurity.org/benchmark/microsoft_365"}
}

func (m *M365DefenderCISModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(m.AzureCredential, nil)
	if err != nil {
		return fmt.Errorf("creating Graph client: %w", err)
	}

	bag := databag.New(m.TenantID, m.TenantDomain)
	collector := collectors.NewGraphCollector(graphClient)
	if err := collector.CollectEntraData(ctx, bag); err != nil {
		slog.Warn("failed to collect Graph data for Defender checks", "error", err)
	}

	// Load and filter check templates
	loader, err := cisdefender.NewLoader()
	if err != nil {
		return fmt.Errorf("loading defender check templates: %w", err)
	}
	allTemplates := loader.GetTemplates()

	includeFilter := plugin.ParseCheckFilter(m.Checks)
	excludeFilter := plugin.ParseCheckFilter(m.ExcludeChecks)
	checkDefs := m365templates.FilterTemplates(allTemplates, includeFilter, excludeFilter)

	cfg.Info("evaluating %d Defender checks", len(checkDefs))

	// Evaluate checks and emit risks
	allResults := evaluateChecks(ctx, cfg, bag, checkDefs, out)

	// Emit compliance map
	compMap := buildComplianceMap(bag, allResults)
	out.Send(compMap)

	return nil
}
