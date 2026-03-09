package recon

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/azure/iam"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() { plugin.Register(&AzureIAMPIMModule{}) }

// IAMPIMConfig holds parameters for the Azure PIM collection module.
type IAMPIMConfig struct {
	plugin.AzureCommonRecon
}

// AzureIAMPIMModule collects PIM (Privileged Identity Management) role
// assignment data.
type AzureIAMPIMModule struct {
	IAMPIMConfig
}

func (m *AzureIAMPIMModule) ID() string                { return "iam-pim" }
func (m *AzureIAMPIMModule) Name() string              { return "Azure PIM Collection" }
func (m *AzureIAMPIMModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureIAMPIMModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureIAMPIMModule) OpsecLevel() string        { return "moderate" }
func (m *AzureIAMPIMModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureIAMPIMModule) Description() string {
	return "Collects PIM (Privileged Identity Management) active and eligible role assignments via Microsoft Graph API. Requires Azure AD Premium P2."
}

func (m *AzureIAMPIMModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview",
	}
}

func (m *AzureIAMPIMModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.EntraID/roleAssignmentScheduleInstances",
		"Microsoft.EntraID/roleEligibilityScheduleInstances",
	}
}

func (m *AzureIAMPIMModule) Parameters() any { return &m.IAMPIMConfig }

func (m *AzureIAMPIMModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	collector := iam.NewPIMCollector(m.AzureCredential)
	result, err := collector.Collect(context.Background())
	if err != nil {
		return err
	}
	out.Send(result)
	return nil
}
