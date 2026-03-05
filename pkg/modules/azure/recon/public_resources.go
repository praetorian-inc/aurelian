package recon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

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
	TemplateDir string `param:"template-dir" desc:"Directory with additional ARG query templates" default:""`
}

// AzurePublicResourcesModule detects publicly accessible Azure resources
// by executing ARG query templates against subscriptions.
type AzurePublicResourcesModule struct {
	AzurePublicResourcesConfig
}

func (m *AzurePublicResourcesModule) ID() string                { return "public-resources" }
func (m *AzurePublicResourcesModule) Name() string              { return "Azure Public Resources" }
func (m *AzurePublicResourcesModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzurePublicResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzurePublicResourcesModule) OpsecLevel() string        { return "stealth" }
func (m *AzurePublicResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzurePublicResourcesModule) Description() string {
	return "Detects publicly accessible Azure resources by executing ARG query templates " +
		"across subscriptions. Uses KQL-based templates to identify storage accounts, " +
		"databases, web apps, and other resources with public network access."
}

func (m *AzurePublicResourcesModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
	}
}

func (m *AzurePublicResourcesModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.Resources/subscriptions",
	}
}

func (m *AzurePublicResourcesModule) Parameters() any {
	return &m.AzurePublicResourcesConfig
}

func (m *AzurePublicResourcesModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	tmplList, err := m.loadTemplates()
	if err != nil {
		return err
	}
	if len(tmplList) == 0 {
		slog.Warn("no ARG query templates loaded")
		return nil
	}

	resolver := subscriptions.NewSubscriptionResolver(m.AzureCredential)
	subIDs, err := resolveSubscriptionIDs(m.SubscriptionID, resolver)
	if err != nil {
		return err
	}
	if len(subIDs) == 0 {
		slog.Warn("no accessible Azure subscriptions found")
		return nil
	}

	idStream := pipeline.From(subIDs...)
	resolvedSubs := pipeline.New[azuretypes.SubscriptionInfo]()
	pipeline.Pipe(idStream, resolver.Resolve, resolvedSubs)

	inputs := pipeline.New[resourcegraph.QueryTemplateInput]()
	pipeline.Pipe(resolvedSubs, fanOutTemplates(tmplList), inputs)

	lister := resourcegraph.NewResourceGraphLister(m.AzureCredential, nil)
	results := pipeline.New[templates.ARGQueryResult]()
	pipeline.Pipe(inputs, queryTemplateWithContinue(lister), results)

	pipeline.Pipe(results, riskFromARGResult, out)

	return out.Wait()
}

func (m *AzurePublicResourcesModule) loadTemplates() ([]*templates.ARGQueryTemplate, error) {
	loader, err := azure.NewLoader()
	if err != nil {
		return nil, fmt.Errorf("failed to load ARG templates: %w", err)
	}

	if m.TemplateDir != "" {
		if err := loader.LoadUserTemplates(m.TemplateDir); err != nil {
			return nil, fmt.Errorf("failed to load user templates: %w", err)
		}
	}

	return loader.GetTemplates(), nil
}

// fanOutTemplates returns a pipeline function that pairs each subscription with every template.
func fanOutTemplates(tmplList []*templates.ARGQueryTemplate) func(azuretypes.SubscriptionInfo, *pipeline.P[resourcegraph.QueryTemplateInput]) error {
	return func(sub azuretypes.SubscriptionInfo, out *pipeline.P[resourcegraph.QueryTemplateInput]) error {
		for _, tmpl := range tmplList {
			out.Send(resourcegraph.QueryTemplateInput{
				Subscription: sub,
				Template:     tmpl,
			})
		}
		return nil
	}
}

// queryTemplateWithContinue returns a pipeline function that executes a template query,
// logging a warning and continuing on failure rather than aborting the pipeline.
func queryTemplateWithContinue(lister *resourcegraph.ResourceGraphLister) func(resourcegraph.QueryTemplateInput, *pipeline.P[templates.ARGQueryResult]) error {
	return func(input resourcegraph.QueryTemplateInput, out *pipeline.P[templates.ARGQueryResult]) error {
		if err := lister.QueryTemplate(input, out); err != nil {
			slog.Warn("template query failed, continuing",
				"template", input.Template.ID,
				"subscription", input.Subscription.ID,
				"error", err,
			)
		}
		return nil
	}
}

func riskFromARGResult(result templates.ARGQueryResult, out *pipeline.P[model.AurelianModel]) error {
	tmpl := result.TemplateDetails
	if tmpl == nil {
		return nil
	}

	severity := mapSeverity(tmpl.Severity)

	contextData := map[string]any{
		"resourceName": result.ResourceName,
		"resourceType": result.ResourceType,
		"location":     result.Location,
		"templateName": tmpl.Name,
		"description":  tmpl.Description,
	}
	if tmpl.TriageNotes != "" {
		contextData["triageNotes"] = tmpl.TriageNotes
	}
	if len(result.Properties) > 0 {
		contextData["properties"] = result.Properties
	}

	ctx, err := json.Marshal(contextData)
	if err != nil {
		slog.Warn("failed to marshal risk context", "template", tmpl.ID, "resource", result.ResourceID, "error", err)
		return nil
	}

	out.Send(output.AurelianRisk{
		Name:        tmpl.ID,
		Severity:    severity,
		ImpactedARN: result.ResourceID,
		Context:     ctx,
	})
	return nil
}

func mapSeverity(s string) output.RiskSeverity {
	switch strings.ToLower(s) {
	case "critical":
		return output.RiskSeverityCritical
	case "high":
		return output.RiskSeverityHigh
	case "medium":
		return output.RiskSeverityMedium
	case "low":
		return output.RiskSeverityLow
	default:
		return output.RiskSeverityInfo
	}
}
