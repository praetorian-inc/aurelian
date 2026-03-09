package recon

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/azure/iam"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() { plugin.Register(&AzureIAMRBACModule{}) }

// IAMRBACConfig holds parameters for the Azure RBAC collection module.
type IAMRBACConfig struct {
	plugin.AzureCommonRecon
}

// AzureIAMRBACModule collects Azure RBAC role assignments and definitions
// across subscriptions.
type AzureIAMRBACModule struct {
	IAMRBACConfig
}

func (m *AzureIAMRBACModule) ID() string                { return "iam-rbac" }
func (m *AzureIAMRBACModule) Name() string              { return "Azure RBAC Collection" }
func (m *AzureIAMRBACModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureIAMRBACModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureIAMRBACModule) OpsecLevel() string        { return "moderate" }
func (m *AzureIAMRBACModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureIAMRBACModule) Description() string {
	return "Collects Azure RBAC role assignments and role definitions for each subscription via the ARM REST API."
}

func (m *AzureIAMRBACModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/role-based-access-control/overview",
	}
}

func (m *AzureIAMRBACModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.Authorization/roleAssignments",
		"Microsoft.Authorization/roleDefinitions",
	}
}

func (m *AzureIAMRBACModule) Parameters() any { return &m.IAMRBACConfig }

func (m *AzureIAMRBACModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	resolver := subscriptions.NewSubscriptionResolver(m.AzureCredential)
	subIDs, err := resolveSubscriptionIDs(m.SubscriptionIDs, resolver)
	if err != nil {
		return err
	}

	collector := iam.NewRBACCollector(m.AzureCredential)
	results, err := collector.Collect(context.Background(), subIDs)
	if err != nil {
		return err
	}
	for _, r := range results {
		out.Send(r)
	}
	return nil
}
