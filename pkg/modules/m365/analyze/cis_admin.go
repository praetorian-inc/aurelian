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
	cisadmin "github.com/praetorian-inc/aurelian/pkg/templates/m365/cis-admin"
)

func init() {
	plugin.Register(&M365AdminCISModule{})
}

type M365AdminCISConfig struct {
	plugin.M365CommonParams
}

type M365AdminCISModule struct {
	M365AdminCISConfig
}

func (m *M365AdminCISModule) ID() string                      { return "cis-admin" }
func (m *M365AdminCISModule) Name() string                    { return "M365 CIS Admin Center Benchmark" }
func (m *M365AdminCISModule) Platform() plugin.Platform       { return plugin.PlatformM365 }
func (m *M365AdminCISModule) Category() plugin.Category       { return plugin.CategoryAnalyze }
func (m *M365AdminCISModule) OpsecLevel() string              { return "safe" }
func (m *M365AdminCISModule) Authors() []string               { return []string{"Praetorian"} }
func (m *M365AdminCISModule) SupportedResourceTypes() []string { return []string{"m365tenant"} }
func (m *M365AdminCISModule) Parameters() any                 { return &m.M365AdminCISConfig }

func (m *M365AdminCISModule) Description() string {
	return "Evaluates Microsoft 365 Admin Center + Purview (Sections 1, 3) against CIS Benchmark v6.0 controls"
}

func (m *M365AdminCISModule) References() []string {
	return []string{"https://www.cisecurity.org/benchmark/microsoft_365"}
}

func (m *M365AdminCISModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
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
		return fmt.Errorf("collecting admin data: %w", err)
	}

	// Load and filter check templates
	loader, err := cisadmin.NewLoader()
	if err != nil {
		return fmt.Errorf("loading admin check templates: %w", err)
	}
	allTemplates := loader.GetTemplates()

	includeFilter := plugin.ParseCheckFilter(m.Checks)
	excludeFilter := plugin.ParseCheckFilter(m.ExcludeChecks)
	checkDefs := m365templates.FilterTemplates(allTemplates, includeFilter, excludeFilter)

	cfg.Info("evaluating %d Admin Center checks", len(checkDefs))

	// Evaluate checks and emit risks
	allResults := evaluateChecks(ctx, cfg, bag, checkDefs, out)

	// Emit compliance map
	compMap := buildComplianceMap(bag, allResults)
	out.Send(compMap)

	return nil
}
