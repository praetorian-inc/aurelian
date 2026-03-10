package recon

import (
	"encoding/json"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	azuretemplates "github.com/praetorian-inc/aurelian/pkg/templates/azure"
)

func init() {
	plugin.Register(&AzurePublicResourcesModule{})
}

// AzurePublicResourcesConfig holds parameters for the Azure public-resources module.
type AzurePublicResourcesConfig struct {
	plugin.AzureCommonRecon
	TemplateDir string `param:"template-dir" desc:"Optional directory with additional YAML query templates" default:""`
}

// AzurePublicResourcesModule identifies publicly accessible Azure resources
// by running ARG query templates against target subscriptions.
type AzurePublicResourcesModule struct {
	AzurePublicResourcesConfig
	templates []*templates.ARGQueryTemplate
}

func (m *AzurePublicResourcesModule) ID() string                { return "public-resources" }
func (m *AzurePublicResourcesModule) Name() string              { return "Azure Public Resources" }
func (m *AzurePublicResourcesModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzurePublicResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzurePublicResourcesModule) OpsecLevel() string        { return "moderate" }
func (m *AzurePublicResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzurePublicResourcesModule) Description() string {
	return "Identifies publicly accessible Azure resources by executing Azure Resource Graph " +
		"query templates against target subscriptions. Detects public storage accounts, " +
		"databases, key vaults, web apps, and other resources exposed to the internet."
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

func (m *AzurePublicResourcesModule) initialize() error {
	loader, err := azuretemplates.NewLoader()
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

func (m *AzurePublicResourcesModule) fanOutTemplates(sub azuretypes.SubscriptionInfo, out *pipeline.P[resourcegraph.QueryInput]) error {
	for _, tmpl := range m.templates {
		out.Send(resourcegraph.QueryInput{Sub: sub, Template: tmpl})
	}
	return nil
}

func (m *AzurePublicResourcesModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	if err := m.initialize(); err != nil {
		return err
	}

	if len(m.templates) == 0 {
		slog.Warn("no azure public resource templates loaded")
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

	results := pipeline.New[templates.ARGQueryResult]()
	lister := resourcegraph.NewResourceGraphLister(m.AzureCredential, nil)
	pipeline.Pipe(inputStream, lister.Query, results)

	pipeline.Pipe(results, resultToRisk, out)

	return out.Wait()
}

func resultToRisk(result templates.ARGQueryResult, out *pipeline.P[model.AurelianModel]) error {
	ctx, err := json.Marshal(result)
	if err != nil {
		slog.Warn("failed to marshal risk context", "template", result.TemplateID, "error", err)
		return nil
	}

	out.Send(output.AurelianRisk{
		Name:        "public-azure-resource",
		Severity:    result.TemplateDetails.Severity,
		ImpactedResourceID: result.ResourceID,
		Context:     ctx,
	})
	return nil
}
