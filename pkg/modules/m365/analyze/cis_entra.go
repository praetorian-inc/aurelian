package analyze

import (
	"context"
	"fmt"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"

	"github.com/praetorian-inc/aurelian/pkg/m365/collectors"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	m365templates "github.com/praetorian-inc/aurelian/pkg/templates/m365"
	cisentra "github.com/praetorian-inc/aurelian/pkg/templates/m365/cis-entra"
)

func init() {
	plugin.Register(&M365EntraCISModule{})
}

// M365EntraCISConfig holds parameters for the CIS Entra module.
type M365EntraCISConfig struct {
	plugin.M365CommonParams
}

// M365EntraCISModule implements CIS Microsoft 365 Entra ID checks.
type M365EntraCISModule struct {
	M365EntraCISConfig
}

func (m *M365EntraCISModule) ID() string                      { return "cis-entra" }
func (m *M365EntraCISModule) Name() string                    { return "M365 CIS Entra ID Benchmark" }
func (m *M365EntraCISModule) Platform() plugin.Platform       { return plugin.PlatformM365 }
func (m *M365EntraCISModule) Category() plugin.Category       { return plugin.CategoryAnalyze }
func (m *M365EntraCISModule) OpsecLevel() string              { return "safe" }
func (m *M365EntraCISModule) Authors() []string               { return []string{"Praetorian"} }
func (m *M365EntraCISModule) SupportedResourceTypes() []string { return []string{"m365tenant"} }
func (m *M365EntraCISModule) Parameters() any                 { return &m.M365EntraCISConfig }

func (m *M365EntraCISModule) Description() string {
	return "Evaluates Microsoft 365 Entra ID (Section 5) against CIS Benchmark v6.0 controls"
}

func (m *M365EntraCISModule) References() []string {
	return []string{
		"https://www.cisecurity.org/benchmark/microsoft_365",
	}
}

func (m *M365EntraCISModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Create Graph client
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(m.AzureCredential, nil)
	if err != nil {
		return fmt.Errorf("creating Graph client: %w", err)
	}

	// 2. Pre-fetch all Entra data into DataBag
	bag := databag.New(m.TenantID, m.TenantDomain)
	collector := collectors.NewGraphCollector(graphClient)
	if err := collector.CollectEntraData(ctx, bag); err != nil {
		return fmt.Errorf("collecting Entra data: %w", err)
	}
	cfg.Info("collected Entra data: %d CA policies, %d roles",
		len(bag.ConditionalAccessPolicies), len(bag.DirectoryRoles))

	// 3. Load and filter check templates
	loader, err := cisentra.NewLoader()
	if err != nil {
		return fmt.Errorf("loading check templates: %w", err)
	}
	allTemplates := loader.GetTemplates()

	includeFilter := plugin.ParseCheckFilter(m.Checks)
	excludeFilter := plugin.ParseCheckFilter(m.ExcludeChecks)
	checkDefs := m365templates.FilterTemplates(allTemplates, includeFilter, excludeFilter)

	cfg.Info("evaluating %d Entra ID checks", len(checkDefs))

	// 4. Evaluate all checks synchronously and collect results
	allResults := evaluateChecks(ctx, cfg, bag, checkDefs, out)

	// 5. Emit compliance map
	compMap := buildComplianceMap(bag, allResults)
	out.Send(compMap)

	return nil
}
