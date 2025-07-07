package hierarchy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/cloudresourcemanager/v1"
)

type GcpOrganizationLister struct {
	*base.GcpReconBaseLink
	resourceManagerService *cloudresourcemanager.Service
}

func NewGcpOrganizationLister(configs ...cfg.Config) chain.Link {
	g := &GcpOrganizationLister{}
	g.GcpReconBaseLink = base.NewGcpReconBaseLink(g, configs...)
	return g
}

func (g *GcpOrganizationLister) Initialize() error {
	if err := g.GcpReconBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return nil
}

func (g *GcpOrganizationLister) Process() error {
	slog.Debug("Listing GCP organizations")
	searchReq := g.resourceManagerService.Organizations.Search(&cloudresourcemanager.SearchOrganizationsRequest{})
	resp, err := searchReq.Do()
	if err != nil {
		return fmt.Errorf("failed to search organizations: %w", err)
	}
	if len(resp.Organizations) == 0 {
		slog.Info("No organizations found")
		return nil
	}
	for _, org := range resp.Organizations {
		gcpOrg := &tab.CloudResource{
			Name:         org.Name,
			DisplayName:  org.DisplayName,
			Provider:     "gcp",
			ResourceType: "gcp_organization",
			Region:       "global",
			AccountRef:   org.Name,
			Properties: map[string]any{
				"displayName":    org.DisplayName,
				"name":           org.Name,
				"lifecycleState": org.LifecycleState,
				"creationTime":   org.CreationTime,
				"owner":          org.Owner,
			},
		}
		slog.Debug("Found organization", "name", org.Name, "displayName", org.DisplayName)
		g.Send(gcpOrg)
	}
	return nil
}
