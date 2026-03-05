package recon

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	azure "github.com/praetorian-inc/aurelian/pkg/templates/azure"
)

func init() {
	plugin.Register(&AzurePublicResourcesModule{})
}

// AzurePublicResourcesConfig holds parameters for the Azure public-resources module.
type AzurePublicResourcesConfig struct {
	plugin.AzureCommonRecon
}

// AzurePublicResourcesModule finds publicly accessible Azure resources via ARG query templates.
type AzurePublicResourcesModule struct {
	AzurePublicResourcesConfig

	publicTemplates []*templates.ARGQueryTemplate
}

func (m *AzurePublicResourcesModule) ID() string                { return "public-resources" }
func (m *AzurePublicResourcesModule) Name() string              { return "Azure Public Resources" }
func (m *AzurePublicResourcesModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzurePublicResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzurePublicResourcesModule) OpsecLevel() string        { return "moderate" }
func (m *AzurePublicResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzurePublicResourcesModule) Description() string {
	return "Finds publicly accessible Azure resources using Azure Resource Graph query templates. " +
		"Scans across subscriptions for resources with public access configurations."
}

func (m *AzurePublicResourcesModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
	}
}

func (m *AzurePublicResourcesModule) SupportedResourceTypes() []string {
	return []string{}
}

func (m *AzurePublicResourcesModule) Parameters() any {
	return &m.AzurePublicResourcesConfig
}

type templateTask struct {
	Sub  azuretypes.SubscriptionInfo
	Tmpl *templates.ARGQueryTemplate
}

func (m *AzurePublicResourcesModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	resolver := subscriptions.NewSubscriptionResolver(m.AzureCredential)

	subscriptionIDs, err := resolveSubscriptionIDs(m.SubscriptionID, resolver)
	if err != nil {
		return err
	}
	if len(subscriptionIDs) == 0 {
		slog.Warn("no accessible Azure subscriptions found")
		return out.Wait()
	}

	idStream := pipeline.From(subscriptionIDs...)
	resolvedSubs := pipeline.New[azuretypes.SubscriptionInfo]()
	pipeline.Pipe(idStream, resolver.Resolve, resolvedSubs)

	loader, err := azure.NewLoader()
	if err != nil {
		return fmt.Errorf("failed to load azure templates: %w", err)
	}

	m.publicTemplates = filterPublicAccessTemplates(loader.GetTemplates())
	if len(m.publicTemplates) == 0 {
		slog.Warn("no Public Access templates found")
		return out.Wait()
	}

	slog.Info("loaded public access templates", "count", len(m.publicTemplates))

	tasks := pipeline.New[templateTask]()
	pipeline.Pipe(resolvedSubs, m.buildTasks, tasks)

	results := pipeline.New[templates.ARGQueryResult]()
	pipeline.Pipe(tasks, m.executeTask, results)

	pipeline.Pipe(results, riskFromQueryResult, out)

	return out.Wait()
}

// buildTasks fans out a subscription into one templateTask per public-access template.
func (m *AzurePublicResourcesModule) buildTasks(sub azuretypes.SubscriptionInfo, out *pipeline.P[templateTask]) error {
	for _, tmpl := range m.publicTemplates {
		out.Send(templateTask{Sub: sub, Tmpl: tmpl})
	}
	return nil
}

// executeTask runs a single template against a subscription.
func (m *AzurePublicResourcesModule) executeTask(task templateTask, out *pipeline.P[templates.ARGQueryResult]) error {
	executor := resourcegraph.NewTemplateExecutor(m.AzureCredential, task.Tmpl)
	return executor.Execute(task.Sub, out)
}

func filterPublicAccessTemplates(all []*templates.ARGQueryTemplate) []*templates.ARGQueryTemplate {
	var filtered []*templates.ARGQueryTemplate
	for _, tmpl := range all {
		for _, cat := range tmpl.Category {
			if cat != string(templates.PublicAccess) {
				continue
			}
			filtered = append(filtered, tmpl)
			break
		}
	}
	return filtered
}

func riskFromQueryResult(r templates.ARGQueryResult, out *pipeline.P[model.AurelianModel]) error {
	if r.ResourceID == "" {
		return nil
	}

	severity := output.RiskSeverityMedium
	if r.TemplateDetails != nil && r.TemplateDetails.Severity != "" {
		severity = output.NormalizeSeverity(r.TemplateDetails.Severity)
	}

	ctx, err := json.Marshal(r)
	if err != nil {
		slog.Warn("failed to build risk context", "resource", r.ResourceID, "error", err)
		return nil
	}

	out.Send(output.AurelianRisk{
		Name:        "public-azure-resource",
		Severity:    severity,
		ImpactedARN: r.ResourceID,
		Context:     ctx,
	})
	return nil
}
