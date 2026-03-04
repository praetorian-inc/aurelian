package recon

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azureauth "github.com/praetorian-inc/aurelian/pkg/azure/auth"
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

var (
	newCredential = azureauth.NewAzureCredential
	newResolver   = func(cred azcore.TokenCredential) subscriptionResolver {
		return subscriptions.NewSubscriptionResolver(cred)
	}
	newLister = func(cred azcore.TokenCredential) resourceLister {
		return resourcegraph.NewResourceGraphLister(cred, nil)
	}
)

type subscriptionResolver interface {
	Resolve(id string, out *pipeline.P[azuretypes.SubscriptionInfo]) error
	ListAllSubscriptions() ([]azuretypes.SubscriptionInfo, error)
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

func (m *AzureListAllResourcesModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	cred, err := newCredential()
	if err != nil {
		return fmt.Errorf("azure authentication failed: %w", err)
	}

	resolver := newResolver(cred)
	lister := newLister(cred)

	subscriptionIDs, err := m.resolveSubscriptionIDs(resolver)
	if err != nil {
		return err
	}

	if len(subscriptionIDs) == 0 {
		slog.Warn("no accessible Azure subscriptions found")
		out.Close()
		return out.Wait()
	}

	idStream := pipeline.From(subscriptionIDs...)
	resolvedSubs := pipeline.New[azuretypes.SubscriptionInfo]()
	pipeline.Pipe(idStream, resolver.Resolve, resolvedSubs)
	pipeline.Pipe(resolvedSubs, lister.ListAll, out)

	return out.Wait()
}

func (m *AzureListAllResourcesModule) resolveSubscriptionIDs(resolver subscriptionResolver) ([]string, error) {
	ids := m.SubscriptionID
	requestsAllSubscriptions := len(ids) == 1 && strings.EqualFold(ids[0], "all")
	if !requestsAllSubscriptions {
		return ids, nil
	}

	subs, err := resolver.ListAllSubscriptions()
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}

	resolvedIDs := make([]string, 0, len(subs))
	for _, sub := range subs {
		resolvedIDs = append(resolvedIDs, sub.ID)
	}
	return resolvedIDs, nil
}
