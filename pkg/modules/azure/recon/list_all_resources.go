package recon

import (
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AzureListAllResourcesModule{})
}

type resourceLister interface {
	ListAll(sub azuretypes.SubscriptionInfo, out *pipeline.P[model.AurelianModel]) error
}

// ListAllConfig holds parameters for the Azure list-all module.
type ListAllConfig struct {
	plugin.AzureCommonRecon
}

// AzureListAllResourcesModule enumerates all Azure resources via Resource Graph.
type AzureListAllResourcesModule struct {
	ListAllConfig
}

func (m *AzureListAllResourcesModule) ID() string                { return "list-all" }
func (m *AzureListAllResourcesModule) Name() string              { return "Azure List All Resources" }
func (m *AzureListAllResourcesModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureListAllResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureListAllResourcesModule) OpsecLevel() string        { return "stealth" }
func (m *AzureListAllResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureListAllResourcesModule) Description() string {
	return "List all Azure resources across subscriptions using Azure Resource Graph. Supports scanning specific subscriptions or all accessible subscriptions."
}

func (m *AzureListAllResourcesModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
		"https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language",
	}
}

func (m *AzureListAllResourcesModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.Resources/subscriptions",
	}
}

func (m *AzureListAllResourcesModule) Parameters() any {
	return &m.ListAllConfig
}

func (m *AzureListAllResourcesModule) Run(_ plugin.Config, resources *pipeline.P[model.AurelianModel]) error {
	resolver := subscriptions.NewSubscriptionResolver(m.AzureCredential)

	subscriptionIDs, err := m.resolveSubscriptionIDs(resolver)
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

	lister := resourcegraph.NewResourceGraphLister(m.AzureCredential, nil)
	pipeline.Pipe(resolvedSubs, lister.ListAll, resources)

	return resources.Wait()
}

func (m *AzureListAllResourcesModule) resolveSubscriptionIDs(resolver subscriptionResolver) ([]string, error) {
	return resolveSubscriptionIDs(m.SubscriptionID, resolver)
}
