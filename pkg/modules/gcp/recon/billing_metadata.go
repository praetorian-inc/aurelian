package recon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	cloudbilling "google.golang.org/api/cloudbilling/v1"
)

func init() {
	plugin.Register(&GCPBillingMetadataModule{})
}

// GCPBillingMetadataConfig holds parameters for the GCP billing-metadata module.
type GCPBillingMetadataConfig struct {
	plugin.GCPCommonRecon
}

// GCPBillingMetadataModule retrieves GCP billing account metadata and project bindings.
type GCPBillingMetadataModule struct {
	GCPBillingMetadataConfig
}

func (m *GCPBillingMetadataModule) ID() string                { return "billing-metadata" }
func (m *GCPBillingMetadataModule) Name() string              { return "GCP Billing Metadata" }
func (m *GCPBillingMetadataModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPBillingMetadataModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPBillingMetadataModule) OpsecLevel() string        { return "moderate" }
func (m *GCPBillingMetadataModule) Authors() []string         { return []string{"Praetorian"} }

func (m *GCPBillingMetadataModule) Description() string {
	return "Enumerate GCP billing accounts and their project bindings. " +
		"Lists all accessible billing accounts and maps projects to their billing configuration."
}

func (m *GCPBillingMetadataModule) References() []string {
	return []string{"https://cloud.google.com/billing/docs/reference/rest"}
}

func (m *GCPBillingMetadataModule) SupportedResourceTypes() []string {
	return nil
}

func (m *GCPBillingMetadataModule) Parameters() any {
	return &m.GCPBillingMetadataConfig
}

func (m *GCPBillingMetadataModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPBillingMetadataConfig
	ctx := context.Background()

	svc, err := cloudbilling.NewService(ctx, c.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating billing service: %w", err)
	}

	summary := &output.GCPBillingSummary{}

	// List all accessible billing accounts.
	err = svc.BillingAccounts.List().Pages(ctx, func(resp *cloudbilling.ListBillingAccountsResponse) error {
		for _, acct := range resp.BillingAccounts {
			summary.BillingAccounts = append(summary.BillingAccounts, output.BillingAccountInfo{
				Name:            acct.Name,
				DisplayName:     acct.DisplayName,
				Open:            acct.Open,
				MasterAccountID: acct.MasterBillingAccount,
			})

			// List projects associated with this billing account.
			listErr := svc.BillingAccounts.Projects.List(acct.Name).Pages(ctx, func(projResp *cloudbilling.ListProjectBillingInfoResponse) error {
				for _, proj := range projResp.ProjectBillingInfo {
					summary.ProjectBindings = append(summary.ProjectBindings, output.ProjectBinding{
						ProjectID:        proj.ProjectId,
						BillingAccountID: proj.BillingAccountName,
						BillingEnabled:   proj.BillingEnabled,
					})
				}
				return nil
			})
			if listErr != nil {
				slog.Warn("failed to list projects for billing account", "account", acct.Name, "error", listErr)
			}
		}
		return nil
	})
	if err != nil {
		if gcperrors.IsDisabledAPI(err) {
			slog.Warn("Cloud Billing API not enabled — enable cloudbilling.googleapis.com or use --quota-project")
		} else if gcperrors.IsPermissionDenied(err) {
			slog.Warn("permission denied listing billing accounts — ensure billing.accounts.list is granted")
		} else {
			slog.Warn("failed to list billing accounts", "error", err)
		}
	}

	// Also get billing info for specifically requested projects that may not
	// have appeared in the billing-account-centric listing above.
	seen := make(map[string]bool, len(summary.ProjectBindings))
	for _, pb := range summary.ProjectBindings {
		seen[pb.ProjectID] = true
	}

	for _, projectID := range c.ProjectID {
		if seen[projectID] {
			continue
		}
		info, getErr := svc.Projects.GetBillingInfo("projects/" + projectID).Context(ctx).Do()
		if getErr != nil {
			if !gcperrors.ShouldSkip(getErr) {
				slog.Warn("failed to get billing info", "project", projectID, "error", getErr)
			}
			continue
		}
		summary.ProjectBindings = append(summary.ProjectBindings, output.ProjectBinding{
			ProjectID:        info.ProjectId,
			BillingAccountID: info.BillingAccountName,
			BillingEnabled:   info.BillingEnabled,
		})
	}

	cfg.Info("\n%s", summary.String())
	out.Send(*summary)
	return nil
}
