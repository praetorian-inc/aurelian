package recon

import (
	"context"
	"log/slog"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/azure/iam"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() { plugin.Register(&AzureIAMPullModule{}) }

// IAMPullConfig holds parameters for the composite Azure IAM pull module.
type IAMPullConfig struct {
	plugin.AzureCommonRecon
}

// AzureIAMPullModule is the composite module that runs all 4 IAM collectors
// sequentially (Entra → PIM → RBAC → MgmtGroups) and emits a consolidated result.
type AzureIAMPullModule struct {
	IAMPullConfig
}

func (m *AzureIAMPullModule) ID() string                { return "iam-pull" }
func (m *AzureIAMPullModule) Name() string              { return "Azure IAM Pull (All)" }
func (m *AzureIAMPullModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureIAMPullModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureIAMPullModule) OpsecLevel() string        { return "moderate" }
func (m *AzureIAMPullModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureIAMPullModule) Description() string {
	return "Composite module that runs all Azure IAM collectors (Entra ID, PIM, RBAC, Management Groups) " +
		"and emits a consolidated result. Equivalent to running iam-entra, iam-pim, iam-rbac, and " +
		"iam-mgmt-groups sequentially."
}

func (m *AzureIAMPullModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/graph/api/overview",
		"https://learn.microsoft.com/en-us/azure/role-based-access-control/overview",
	}
}

func (m *AzureIAMPullModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.EntraID/users",
		"Microsoft.EntraID/groups",
		"Microsoft.EntraID/servicePrincipals",
		"Microsoft.EntraID/applications",
		"Microsoft.Authorization/roleAssignments",
		"Microsoft.Authorization/roleDefinitions",
		"Microsoft.Management/managementGroups",
	}
}

func (m *AzureIAMPullModule) Parameters() any { return &m.IAMPullConfig }

func (m *AzureIAMPullModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := context.Background()
	consolidated := &types.AzureIAMConsolidated{}

	// 1. Entra ID
	slog.Info("collecting Entra ID data")
	entraCollector := iam.NewEntraCollector(m.AzureCredential)
	entraData, err := entraCollector.Collect(ctx)
	if err != nil {
		slog.Warn("Entra ID collection failed", "error", err)
	} else {
		consolidated.EntraID = entraData
		slog.Info("Entra ID collection complete",
			"users", entraData.Users.Len(),
			"groups", entraData.Groups.Len(),
			"servicePrincipals", entraData.ServicePrincipals.Len(),
			"applications", entraData.Applications.Len(),
		)
	}

	// 2. PIM
	slog.Info("collecting PIM data")
	pimCollector := iam.NewPIMCollector(m.AzureCredential)
	pimData, err := pimCollector.Collect(ctx)
	if err != nil {
		slog.Warn("PIM collection failed", "error", err)
	} else {
		consolidated.PIM = pimData
		slog.Info("PIM collection complete",
			"activeAssignments", len(pimData.ActiveAssignments),
			"eligibleAssignments", len(pimData.EligibleAssignments),
		)
	}

	// 3. RBAC
	slog.Info("collecting RBAC data")
	resolver := subscriptions.NewSubscriptionResolver(m.AzureCredential)
	subIDs, err := resolveSubscriptionIDs(m.SubscriptionIDs, resolver)
	if err != nil {
		slog.Warn("failed to resolve subscription IDs", "error", err)
	} else if len(subIDs) > 0 {
		rbacCollector := iam.NewRBACCollector(m.AzureCredential)
		rbacData, err := rbacCollector.Collect(ctx, subIDs)
		if err != nil {
			slog.Warn("RBAC collection failed", "error", err)
		} else {
			consolidated.RBAC = rbacData
			slog.Info("RBAC collection complete", "subscriptions", len(rbacData))
		}
	} else {
		slog.Warn("no accessible subscriptions found, skipping RBAC collection")
	}

	// 4. Management Groups
	slog.Info("collecting management group hierarchy")
	mgCollector := iam.NewMgmtGroupsCollector(m.AzureCredential)
	mgData, err := mgCollector.Collect(ctx)
	if err != nil {
		slog.Warn("management group collection failed", "error", err)
	} else {
		consolidated.ManagementGroups = mgData
		slog.Info("management group collection complete",
			"groups", len(mgData.Groups),
			"relationships", len(mgData.Relationships),
		)
	}

	// Populate collection metadata
	consolidated.Metadata = &types.CollectionMetadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Counts:    buildEntityCounts(consolidated),
	}

	out.Send(consolidated)
	return nil
}

// buildEntityCounts summarizes entity counts from the consolidated data.
func buildEntityCounts(c *types.AzureIAMConsolidated) map[string]int {
	counts := make(map[string]int)
	if c.EntraID != nil {
		counts["users"] = c.EntraID.Users.Len()
		counts["groups"] = c.EntraID.Groups.Len()
		counts["servicePrincipals"] = c.EntraID.ServicePrincipals.Len()
		counts["applications"] = c.EntraID.Applications.Len()
		counts["devices"] = len(c.EntraID.Devices)
		counts["directoryRoles"] = len(c.EntraID.DirectoryRoles)
		counts["groupMemberships"] = len(c.EntraID.GroupMemberships)
		counts["ownershipRelationships"] = len(c.EntraID.OwnershipRelationships)
	}
	if c.PIM != nil {
		counts["pimActiveAssignments"] = len(c.PIM.ActiveAssignments)
		counts["pimEligibleAssignments"] = len(c.PIM.EligibleAssignments)
	}
	if c.RBAC != nil {
		counts["rbacSubscriptions"] = len(c.RBAC)
	}
	if c.ManagementGroups != nil {
		counts["managementGroups"] = len(c.ManagementGroups.Groups)
		counts["mgmtGroupRelationships"] = len(c.ManagementGroups.Relationships)
	}
	return counts
}
