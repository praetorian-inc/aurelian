package recon

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/azure/iam"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() { plugin.Register(&AzureIAMManagedIdentityModule{}) }

// IAMManagedIdentityConfig holds parameters for the Azure Managed Identity
// collection module.
type IAMManagedIdentityConfig struct {
	plugin.AzureCommonRecon
}

// AzureIAMManagedIdentityModule collects Azure managed identity data including
// user-assigned identities and resource identity attachments.
type AzureIAMManagedIdentityModule struct {
	IAMManagedIdentityConfig
}

func (m *AzureIAMManagedIdentityModule) ID() string                { return "iam-managed-identity" }
func (m *AzureIAMManagedIdentityModule) Name() string              { return "Azure Managed Identity Collection" }
func (m *AzureIAMManagedIdentityModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureIAMManagedIdentityModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureIAMManagedIdentityModule) OpsecLevel() string        { return "moderate" }
func (m *AzureIAMManagedIdentityModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureIAMManagedIdentityModule) Description() string {
	return "Collects Azure user-assigned managed identities and resource identity attachments " +
		"via ARM REST API and Azure Resource Graph."
}

func (m *AzureIAMManagedIdentityModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview",
	}
}

func (m *AzureIAMManagedIdentityModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.ManagedIdentity/userAssignedIdentities",
	}
}

func (m *AzureIAMManagedIdentityModule) Parameters() any { return &m.IAMManagedIdentityConfig }

func (m *AzureIAMManagedIdentityModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	resolver := subscriptions.NewSubscriptionResolver(m.AzureCredential)
	subIDs, err := resolveSubscriptionIDs(m.SubscriptionIDs, resolver)
	if err != nil {
		return err
	}

	collector := iam.NewManagedIdentityCollector(m.AzureCredential)
	result, err := collector.Collect(context.Background(), subIDs)
	if err != nil {
		return err
	}
	out.Send(result)
	return nil
}
