package recon

import (
	"context"
	"fmt"

	azurehelpers "github.com/praetorian-inc/aurelian/internal/helpers/azure"
	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AzureListAllResourcesModule{})
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
	return []string{"Azure::Resources::Resource"}
}

func (m *AzureListAllResourcesModule) Parameters() any {
	return &m.ListAllConfig
}

func (m *AzureListAllResourcesModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.ListAllConfig
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	cred, err := azurehelpers.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("azure authentication failed: %w", err)
	}

	subs, err := azurehelpers.ResolveSubscriptions(ctx, cred, c.SubscriptionID)
	if err != nil {
		return fmt.Errorf("failed to resolve subscriptions: %w", err)
	}

	lister, err := resourcegraph.NewResourceGraphLister(cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create resource graph lister: %w", err)
	}

	return lister.ListAll(ctx, subs, out)
}
