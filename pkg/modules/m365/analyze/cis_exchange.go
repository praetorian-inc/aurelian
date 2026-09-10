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
	cisexchange "github.com/praetorian-inc/aurelian/pkg/templates/m365/cis-exchange"
)

func init() {
	plugin.Register(&M365ExchangeCISModule{})
}

type M365ExchangeCISConfig struct {
	plugin.M365PowerShellParams
}

type M365ExchangeCISModule struct {
	M365ExchangeCISConfig
}

func (m *M365ExchangeCISModule) ID() string                      { return "cis-exchange" }
func (m *M365ExchangeCISModule) Name() string                    { return "M365 CIS Exchange Online Benchmark" }
func (m *M365ExchangeCISModule) Platform() plugin.Platform       { return plugin.PlatformM365 }
func (m *M365ExchangeCISModule) Category() plugin.Category       { return plugin.CategoryAnalyze }
func (m *M365ExchangeCISModule) OpsecLevel() string              { return "safe" }
func (m *M365ExchangeCISModule) Authors() []string               { return []string{"Praetorian"} }
func (m *M365ExchangeCISModule) SupportedResourceTypes() []string { return []string{"m365tenant"} }
func (m *M365ExchangeCISModule) Parameters() any                 { return &m.M365ExchangeCISConfig }

func (m *M365ExchangeCISModule) Description() string {
	return "Evaluates Microsoft 365 Exchange Online (Section 6) against CIS Benchmark v6.0 controls"
}

func (m *M365ExchangeCISModule) References() []string {
	return []string{"https://www.cisecurity.org/benchmark/microsoft_365"}
}

func (m *M365ExchangeCISModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
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
		slog.Warn("failed to collect Graph data for Exchange checks", "error", err)
	}

	// 2. Collect PowerShell data
	if !m.SkipPowerShell && m.PowerShellAvailable {
		cfg.Info("collecting Exchange Online data via PowerShell...")
		psCollector := collectors.NewPowerShellCollector(m.PowerShellPath)
		if err := psCollector.CollectExchangeData(ctx, bag); err != nil {
			slog.Warn("failed to collect Exchange data via PowerShell", "error", err)
		}
	} else if !m.SkipPowerShell && !m.PowerShellAvailable {
		cfg.Fail("PowerShell (pwsh) not found — Exchange data was NOT collected. Install PowerShell 7+ (https://aka.ms/powershell) or use --skip-powershell to skip these checks.")
	}

	// 3. Load and filter check templates
	loader, err := cisexchange.NewLoader()
	if err != nil {
		return fmt.Errorf("loading Exchange check templates: %w", err)
	}
	allTemplates := loader.GetTemplates()

	includeFilter := plugin.ParseCheckFilter(m.Checks)
	excludeFilter := plugin.ParseCheckFilter(m.ExcludeChecks)
	checkDefs := m365templates.FilterTemplates(allTemplates, includeFilter, excludeFilter)

	cfg.Info("evaluating %d Exchange Online checks", len(checkDefs))

	// 4. Evaluate all checks synchronously and collect results
	allResults := evaluateChecks(ctx, cfg, bag, checkDefs, out)

	// 5. Emit compliance map
	compMap := buildComplianceMap(bag, allResults)
	out.Send(compMap)

	return nil
}
