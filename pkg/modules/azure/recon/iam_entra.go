package recon

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/azure/iam"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() { plugin.Register(&AzureIAMEntraModule{}) }

// IAMEntraConfig holds parameters for the Azure Entra ID collection module.
type IAMEntraConfig struct {
	plugin.AzureCommonRecon
}

// AzureIAMEntraModule collects Entra ID (Azure AD) identity data.
type AzureIAMEntraModule struct {
	IAMEntraConfig
}

func (m *AzureIAMEntraModule) ID() string                { return "iam-entra" }
func (m *AzureIAMEntraModule) Name() string              { return "Azure Entra ID Collection" }
func (m *AzureIAMEntraModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureIAMEntraModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureIAMEntraModule) OpsecLevel() string        { return "moderate" }
func (m *AzureIAMEntraModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureIAMEntraModule) Description() string {
	return "Collects Entra ID (Azure AD) identity data: users, groups, service principals, applications, devices, roles, policies, memberships, and ownership relationships via Microsoft Graph API."
}

func (m *AzureIAMEntraModule) References() []string {
	return []string{"https://learn.microsoft.com/en-us/graph/api/overview"}
}

func (m *AzureIAMEntraModule) SupportedResourceTypes() []string {
	return []string{"Microsoft.EntraID/tenant"}
}

func (m *AzureIAMEntraModule) Parameters() any { return &m.IAMEntraConfig }

func (m *AzureIAMEntraModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	collector := iam.NewEntraCollector(m.AzureCredential)
	result, err := collector.Collect(context.Background())
	if err != nil {
		return err
	}
	out.Send(result)
	return nil
}
