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
	cissharepoint "github.com/praetorian-inc/aurelian/pkg/templates/m365/cis-sharepoint"
)

func init() {
	plugin.Register(&M365SharePointCISModule{})
}

type M365SharePointCISConfig struct {
	plugin.M365PowerShellParams
}

type M365SharePointCISModule struct {
	M365SharePointCISConfig
}

func (m *M365SharePointCISModule) ID() string                      { return "cis-sharepoint" }
func (m *M365SharePointCISModule) Name() string                    { return "M365 CIS SharePoint Online Benchmark" }
func (m *M365SharePointCISModule) Platform() plugin.Platform       { return plugin.PlatformM365 }
func (m *M365SharePointCISModule) Category() plugin.Category       { return plugin.CategoryAnalyze }
func (m *M365SharePointCISModule) OpsecLevel() string              { return "safe" }
func (m *M365SharePointCISModule) Authors() []string               { return []string{"Praetorian"} }
func (m *M365SharePointCISModule) SupportedResourceTypes() []string { return []string{"m365tenant"} }
func (m *M365SharePointCISModule) Parameters() any                 { return &m.M365SharePointCISConfig }

func (m *M365SharePointCISModule) Description() string {
	return "Evaluates Microsoft 365 SharePoint Online (Section 7) against CIS Benchmark v6.0 controls"
}

func (m *M365SharePointCISModule) References() []string {
	return []string{"https://www.cisecurity.org/benchmark/microsoft_365"}
}

func (m *M365SharePointCISModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
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
		slog.Warn("failed to collect Graph data for SharePoint checks", "error", err)
	}

	// 2. Collect PowerShell data
	if !m.SkipPowerShell && m.PowerShellAvailable {
		if m.SharePointAdminURL == "" {
			cfg.Fail("SharePoint admin URL is required for PowerShell collection — use --sharepoint-admin-url or ensure --tenant-domain is set")
		} else {
			cfg.Info("collecting SharePoint Online data via PowerShell...")
			psCollector := collectors.NewPowerShellCollector(m.PowerShellPath)
			if err := psCollector.CollectSharePointData(ctx, bag, m.SharePointAdminURL); err != nil {
				slog.Warn("failed to collect SharePoint data via PowerShell", "error", err)
			}
		}
	} else if !m.SkipPowerShell && !m.PowerShellAvailable {
		cfg.Fail("PowerShell (pwsh) not found — SharePoint data was NOT collected. Install PowerShell 7+ (https://aka.ms/powershell) or use --skip-powershell to skip these checks.")
	}

	// 3. Load and filter check templates
	loader, err := cissharepoint.NewLoader()
	if err != nil {
		return fmt.Errorf("loading SharePoint check templates: %w", err)
	}
	allTemplates := loader.GetTemplates()

	includeFilter := plugin.ParseCheckFilter(m.Checks)
	excludeFilter := plugin.ParseCheckFilter(m.ExcludeChecks)
	checkDefs := m365templates.FilterTemplates(allTemplates, includeFilter, excludeFilter)

	cfg.Info("evaluating %d SharePoint Online checks", len(checkDefs))

	// 4. Evaluate all checks synchronously and collect results
	allResults := evaluateChecks(ctx, cfg, bag, checkDefs, out)

	// 5. Emit compliance map
	compMap := buildComplianceMap(bag, allResults)
	out.Send(compMap)

	return nil
}
