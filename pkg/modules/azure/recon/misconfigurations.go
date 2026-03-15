package recon

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/azure/misconfigcheck"
	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	misconfigtemplates "github.com/praetorian-inc/aurelian/pkg/templates/azure/misconfigurations"
)

func init() {
	plugin.Register(&AzureMisconfigurationsModule{})
}

type AzureMisconfigurationsConfig struct {
	plugin.AzureCommonRecon
	TemplateDir string `param:"template-dir" desc:"Optional directory with additional YAML query templates" default:""`
}

type AzureMisconfigurationsModule struct {
	AzureMisconfigurationsConfig
	templates []*templates.ARGQueryTemplate
}

func (m *AzureMisconfigurationsModule) ID() string                { return "misconfigurations" }
func (m *AzureMisconfigurationsModule) Name() string              { return "Azure Misconfigurations" }
func (m *AzureMisconfigurationsModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureMisconfigurationsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureMisconfigurationsModule) OpsecLevel() string        { return "moderate" }
func (m *AzureMisconfigurationsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureMisconfigurationsModule) Description() string {
	return "Detects Azure misconfigurations including weak authentication, disabled RBAC, " +
		"privilege escalation paths, and overly permissive access rules via Azure Resource Graph."
}

func (m *AzureMisconfigurationsModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
	}
}

func (m *AzureMisconfigurationsModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.Resources/subscriptions",
	}
}

func (m *AzureMisconfigurationsModule) Parameters() any {
	return &m.AzureMisconfigurationsConfig
}

func (m *AzureMisconfigurationsModule) initialize() error {
	loader, err := misconfigtemplates.NewLoader()
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

func (m *AzureMisconfigurationsModule) fanOutTemplates(sub azuretypes.SubscriptionInfo, out *pipeline.P[resourcegraph.QueryInput]) error {
	for _, tmpl := range m.templates {
		out.Send(resourcegraph.QueryInput{Sub: sub, Template: tmpl})
	}
	return nil
}

func (m *AzureMisconfigurationsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	if err := m.initialize(); err != nil {
		return err
	}

	if len(m.templates) == 0 {
		slog.Warn("no azure misconfiguration templates loaded")
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

	// Enrichment: confirm enricher-dependent templates via SDK API calls.
	// Templates with ARG-level filtering pass through unchanged.
	enricher := misconfigcheck.NewEnricher(ctx, m.AzureCredential)
	confirmed := pipeline.New[templates.ARGQueryResult]()
	pipeline.Pipe(candidates, enricher.Enrich, confirmed)

	pipeline.Pipe(confirmed, misconfigToRisk, out)

	return out.Wait()
}

func misconfigToRisk(result templates.ARGQueryResult, out *pipeline.P[model.AurelianModel]) error {
	ctx, err := json.Marshal(result)
	if err != nil {
		slog.Warn("failed to marshal risk context", "template", result.TemplateID, "error", err)
		return nil
	}

	out.Send(output.AurelianRisk{
		Name:               "azure-misconfiguration",
		Severity:           result.TemplateDetails.Severity,
		ImpactedResourceID: result.ResourceID,
		Context:            ctx,
	})
	return nil
}
