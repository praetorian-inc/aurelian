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
	cisteams "github.com/praetorian-inc/aurelian/pkg/templates/m365/cis-teams"
)

func init() {
	plugin.Register(&M365TeamsCISModule{})
}

type M365TeamsCISConfig struct {
	plugin.M365PowerShellParams
}

type M365TeamsCISModule struct {
	M365TeamsCISConfig
}

func (m *M365TeamsCISModule) ID() string                      { return "cis-teams" }
func (m *M365TeamsCISModule) Name() string                    { return "M365 CIS Teams Benchmark" }
func (m *M365TeamsCISModule) Platform() plugin.Platform       { return plugin.PlatformM365 }
func (m *M365TeamsCISModule) Category() plugin.Category       { return plugin.CategoryAnalyze }
func (m *M365TeamsCISModule) OpsecLevel() string              { return "safe" }
func (m *M365TeamsCISModule) Authors() []string               { return []string{"Praetorian"} }
func (m *M365TeamsCISModule) SupportedResourceTypes() []string { return []string{"m365tenant"} }
func (m *M365TeamsCISModule) Parameters() any                 { return &m.M365TeamsCISConfig }

func (m *M365TeamsCISModule) Description() string {
	return "Evaluates Microsoft 365 Teams (Section 8) against CIS Benchmark v6.0 controls"
}

func (m *M365TeamsCISModule) References() []string {
	return []string{"https://www.cisecurity.org/benchmark/microsoft_365"}
}

func (m *M365TeamsCISModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Create Graph client and collect Graph-sourced data
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(m.AzureCredential, nil)
	if err != nil {
		return fmt.Errorf("creating Graph client: %w", err)
	}

	bag := databag.New(m.TenantID, m.TenantDomain)
	graphCollector := collectors.NewGraphCollector(graphClient)
	if err := graphCollector.CollectEntraData(ctx, bag); err != nil {
		slog.Warn("failed to collect Graph data for Teams checks", "error", err)
	}

	// 2. Collect PowerShell data
	if !m.SkipPowerShell && m.PowerShellAvailable {
		cfg.Info("collecting Teams data via PowerShell...")
		psCollector := collectors.NewPowerShellCollector(m.PowerShellPath)
		if err := psCollector.CollectTeamsData(ctx, bag); err != nil {
			slog.Warn("failed to collect Teams data via PowerShell", "error", err)
		}
	} else if !m.SkipPowerShell && !m.PowerShellAvailable {
		cfg.Fail("PowerShell (pwsh) not found — Teams data was NOT collected. Install PowerShell 7+ (https://aka.ms/powershell) or use --skip-powershell to skip these checks.")
	}

	// 3. Load and filter check templates
	loader, err := cisteams.NewLoader()
	if err != nil {
		return fmt.Errorf("loading Teams check templates: %w", err)
	}
	allTemplates := loader.GetTemplates()

	includeFilter := plugin.ParseCheckFilter(m.Checks)
	excludeFilter := plugin.ParseCheckFilter(m.ExcludeChecks)
	checkDefs := m365templates.FilterTemplates(allTemplates, includeFilter, excludeFilter)

	cfg.Info("evaluating %d Teams checks", len(checkDefs))

	// 4. Evaluate all checks synchronously and collect results
	allResults := evaluateChecks(ctx, cfg, bag, checkDefs, out)

	// 5. Emit compliance map
	compMap := buildComplianceMap(bag, allResults)
	out.Send(compMap)

	return nil
}
