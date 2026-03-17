package recon

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/azure/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	configscantemplates "github.com/praetorian-inc/aurelian/pkg/templates/azure/configuration-scan"
)

func init() {
	plugin.Register(&AzureConfigurationScanModule{})
}

type AzureConfigurationScanConfig struct {
	plugin.AzureCommonRecon
	TemplateDir      string `param:"template-dir"      desc:"Optional directory with additional YAML query templates" default:""`
	Concurrency      int    `param:"concurrency"       desc:"Maximum concurrent API requests" default:"10"`
	EnricherTimeout  int    `param:"enricher-timeout"  desc:"Per-resource enricher timeout in seconds" default:"120"`
}

type AzureConfigurationScanModule struct {
	AzureConfigurationScanConfig
	templates []*templates.ARGQueryTemplate
}

func (m *AzureConfigurationScanModule) ID() string                { return "configuration-scan" }
func (m *AzureConfigurationScanModule) Name() string              { return "Azure Configuration Scan" }
func (m *AzureConfigurationScanModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureConfigurationScanModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureConfigurationScanModule) OpsecLevel() string        { return "moderate" }
func (m *AzureConfigurationScanModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureConfigurationScanModule) Description() string {
	return "Detects Azure configuration issues including weak authentication, disabled RBAC, " +
		"privilege escalation paths, and overly permissive access rules via Azure Resource Graph."
}

func (m *AzureConfigurationScanModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
	}
}

func (m *AzureConfigurationScanModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.Resources/subscriptions",
	}
}

func (m *AzureConfigurationScanModule) Parameters() any {
	return &m.AzureConfigurationScanConfig
}

func (m *AzureConfigurationScanModule) initialize() error {
	loader, err := configscantemplates.NewLoader()
	if err != nil {
		return err
	}

	if m.TemplateDir != "" {
		if err := loader.LoadUserTemplates(m.TemplateDir); err != nil {
			return err
		}
	}

	m.templates = loader.GetTemplates()
	return nil
}

func (m *AzureConfigurationScanModule) fanOutTemplates(sub azuretypes.SubscriptionInfo, out *pipeline.P[resourcegraph.QueryInput]) error {
	for _, tmpl := range m.templates {
		out.Send(resourcegraph.QueryInput{Sub: sub, Template: tmpl})
	}
	return nil
}

func (m *AzureConfigurationScanModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	if err := m.initialize(); err != nil {
		return err
	}

	if len(m.templates) == 0 {
		slog.Warn("no azure configuration scan templates loaded")
		return nil
	}

	resolver := subscriptions.NewSubscriptionResolver(m.AzureCredential)
	subscriptionIDs, err := resolveSubscriptionIDs(m.SubscriptionIDs, resolver)
	if err != nil {
		return err
	}

	if len(subscriptionIDs) == 0 {
		slog.Warn("no accessible Azure subscriptions found")
		return nil
	}

	idStream := pipeline.From(subscriptionIDs...)
	resolvedSubs := pipeline.New[azuretypes.SubscriptionInfo]()
	pipeline.Pipe(idStream, resolver.Resolve, resolvedSubs)

	inputStream := pipeline.New[resourcegraph.QueryInput]()
	pipeline.Pipe(resolvedSubs, m.fanOutTemplates, inputStream)

	candidates := pipeline.New[templates.ARGQueryResult]()
	lister := resourcegraph.NewResourceGraphLister(m.AzureCredential, nil)
	pipeline.Pipe(inputStream, lister.Query, candidates)

	enricherTimeout := time.Duration(m.EnricherTimeout) * time.Second
	enricher := enrichment.NewAzureEnricher(ctx, m.AzureCredential, enricherTimeout)
	enriched := pipeline.New[templates.ARGQueryResult]()
	pipeline.Pipe(candidates, enricher.Enrich, enriched, &pipeline.PipeOpts{
		Concurrency: m.Concurrency,
	})

	confirmed := pipeline.New[templates.ARGQueryResult]()
	pipeline.Pipe(enriched, enrichment.Evaluate, confirmed, &pipeline.PipeOpts{
		Concurrency: m.Concurrency,
	})

	pipeline.Pipe(confirmed, configScanToRisk, out)

	return out.Wait()
}

func configScanToRisk(result templates.ARGQueryResult, out *pipeline.P[model.AurelianModel]) error {
	ctx, err := json.Marshal(result)
	if err != nil {
		slog.Warn("failed to marshal risk context", "template", result.TemplateID, "error", err)
		return nil
	}

	out.Send(output.AurelianRisk{
		Name:               "azure-configuration-scan",
		Severity:           result.TemplateDetails.Severity,
		ImpactedResourceID: result.ResourceID,
		Context:            ctx,
	})
	return nil
}
