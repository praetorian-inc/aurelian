package recon

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/azure/iam"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() { plugin.Register(&AzureIAMMgmtGroupsModule{}) }

// IAMMgmtGroupsConfig holds parameters for the Azure Management Groups
// collection module.
type IAMMgmtGroupsConfig struct {
	plugin.AzureCommonRecon
}

// AzureIAMMgmtGroupsModule collects Azure management group hierarchy data.
type AzureIAMMgmtGroupsModule struct {
	IAMMgmtGroupsConfig
}

func (m *AzureIAMMgmtGroupsModule) ID() string                { return "iam-mgmt-groups" }
func (m *AzureIAMMgmtGroupsModule) Name() string              { return "Azure Management Groups Collection" }
func (m *AzureIAMMgmtGroupsModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureIAMMgmtGroupsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureIAMMgmtGroupsModule) OpsecLevel() string        { return "moderate" }
func (m *AzureIAMMgmtGroupsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureIAMMgmtGroupsModule) Description() string {
	return "Collects Azure management group hierarchy including parent-child relationships between management groups and subscriptions."
}

func (m *AzureIAMMgmtGroupsModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/governance/management-groups/overview",
	}
}

func (m *AzureIAMMgmtGroupsModule) SupportedResourceTypes() []string {
	return []string{"Microsoft.EntraID/tenant"}
}

func (m *AzureIAMMgmtGroupsModule) Parameters() any { return &m.IAMMgmtGroupsConfig }

func (m *AzureIAMMgmtGroupsModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	collector := iam.NewMgmtGroupsCollector(m.AzureCredential)
	result, err := collector.Collect(context.Background())
	if err != nil {
		return err
	}
	out.Send(result)
	return nil
}
