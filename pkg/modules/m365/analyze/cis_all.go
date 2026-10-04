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
	cisentra "github.com/praetorian-inc/aurelian/pkg/templates/m365/cis-entra"
	cisexchange "github.com/praetorian-inc/aurelian/pkg/templates/m365/cis-exchange"
	cissharepoint "github.com/praetorian-inc/aurelian/pkg/templates/m365/cis-sharepoint"
	cisteams "github.com/praetorian-inc/aurelian/pkg/templates/m365/cis-teams"
)

func init() {
	plugin.Register(&M365AllCISModule{})
}

type M365AllCISConfig struct {
	plugin.M365PowerShellParams
}

type M365AllCISModule struct {
	M365AllCISConfig
}

func (m *M365AllCISModule) ID() string                      { return "cis-all" }
func (m *M365AllCISModule) Name() string                    { return "M365 CIS Full Benchmark" }
func (m *M365AllCISModule) Platform() plugin.Platform       { return plugin.PlatformM365 }
func (m *M365AllCISModule) Category() plugin.Category       { return plugin.CategoryAnalyze }
func (m *M365AllCISModule) OpsecLevel() string              { return "safe" }
func (m *M365AllCISModule) Authors() []string               { return []string{"Praetorian"} }
func (m *M365AllCISModule) SupportedResourceTypes() []string { return []string{"m365tenant"} }
func (m *M365AllCISModule) Parameters() any                 { return &m.M365AllCISConfig }

func (m *M365AllCISModule) Description() string {
	return "Runs all M365 CIS Benchmark v6.0 checks (meta-module combining all service areas)"
}

func (m *M365AllCISModule) References() []string {
	return []string{"https://www.cisecurity.org/benchmark/microsoft_365"}
}

func (m *M365AllCISModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Create Graph client
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(m.AzureCredential, nil)
	if err != nil {
		return fmt.Errorf("creating Graph client: %w", err)
	}

	// 2. Pre-fetch Graph data for all service areas
	bag := databag.New(m.TenantID, m.TenantDomain)
	graphCollector := collectors.NewGraphCollector(graphClient)

	cfg.Info("collecting Entra ID data...")
	if err := graphCollector.CollectEntraData(ctx, bag); err != nil {
		slog.Warn("failed to collect Entra data", "error", err)
	}

	cfg.Info("collected data: %d CA policies, %d directory roles",
		len(bag.ConditionalAccessPolicies), len(bag.DirectoryRoles))

	// 3. Collect PowerShell data for Exchange, Teams, SharePoint
	if !m.SkipPowerShell && m.PowerShellAvailable {
		psCollector := collectors.NewPowerShellCollector(m.PowerShellPath)

		cfg.Info("collecting Exchange Online data via PowerShell...")
		if err := psCollector.CollectExchangeData(ctx, bag); err != nil {
			slog.Warn("failed to collect Exchange data via PowerShell", "error", err)
		}

		cfg.Info("collecting Teams data via PowerShell...")
		if err := psCollector.CollectTeamsData(ctx, bag); err != nil {
			slog.Warn("failed to collect Teams data via PowerShell", "error", err)
		}

		if m.SharePointAdminURL != "" {
			cfg.Info("collecting SharePoint Online data via PowerShell...")
			if err := psCollector.CollectSharePointData(ctx, bag, m.SharePointAdminURL); err != nil {
				slog.Warn("failed to collect SharePoint data via PowerShell", "error", err)
			}
		} else {
			cfg.Warn("SharePoint admin URL not set — skipping SharePoint PowerShell collection. Use --sharepoint-admin-url to enable.")
		}
	} else if !m.SkipPowerShell && !m.PowerShellAvailable {
		cfg.Fail("PowerShell (pwsh) not found — Exchange/Teams/SharePoint data was NOT collected. Install PowerShell 7+ (https://aka.ms/powershell) or use --skip-powershell to skip these checks.")
	}

	// 4. Load all available templates
	var allTemplates []*m365templates.M365CheckTemplate

	entraLoader, err := cisentra.NewLoader()
	if err != nil {
		slog.Warn("failed to load Entra templates", "error", err)
	} else {
		allTemplates = append(allTemplates, entraLoader.GetTemplates()...)
	}

	exchangeLoader, err := cisexchange.NewLoader()
	if err != nil {
		slog.Warn("failed to load Exchange templates", "error", err)
	} else {
		allTemplates = append(allTemplates, exchangeLoader.GetTemplates()...)
	}

	teamsLoader, err := cisteams.NewLoader()
	if err != nil {
		slog.Warn("failed to load Teams templates", "error", err)
	} else {
		allTemplates = append(allTemplates, teamsLoader.GetTemplates()...)
	}

	sharePointLoader, err := cissharepoint.NewLoader()
	if err != nil {
		slog.Warn("failed to load SharePoint templates", "error", err)
	} else {
		allTemplates = append(allTemplates, sharePointLoader.GetTemplates()...)
	}

	includeFilter := plugin.ParseCheckFilter(m.Checks)
	excludeFilter := plugin.ParseCheckFilter(m.ExcludeChecks)
	checkDefs := m365templates.FilterTemplates(allTemplates, includeFilter, excludeFilter)

	cfg.Info("evaluating %d CIS checks across all service areas", len(checkDefs))

	// 5. Evaluate all checks synchronously and collect results
	allResults := evaluateChecks(ctx, cfg, bag, checkDefs, out)

	// 6. Emit compliance map
	compMap := buildComplianceMap(bag, allResults)
	out.Send(compMap)

	return nil
}
