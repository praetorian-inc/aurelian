package hierarchy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/cloudresourcemanager/v2"
)

type GcpFolderLister struct {
	*base.GcpReconBaseLink
	resourceManagerService *cloudresourcemanager.Service
	Parent                 string
}

func NewGcpFolderLister(configs ...cfg.Config) chain.Link {
	g := &GcpFolderLister{}
	g.GcpReconBaseLink = base.NewGcpReconBaseLink(g, configs...)
	return g
}

func (g *GcpFolderLister) Params() []cfg.Param {
	params := g.GcpReconBaseLink.Params()
	params = append(params, cfg.NewParam[string]("parent", "Parent resource (organization/folder) to list folders under").WithDefault(""))
	return params
}

func (g *GcpFolderLister) Initialize() error {
	if err := g.GcpReconBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	parent, err := cfg.As[string](g.Arg("parent"))
	if err != nil {
		return fmt.Errorf("failed to get parent: %w", err)
	}
	g.Parent = parent
	return nil
}

func (g *GcpFolderLister) Process() error {
	slog.Debug("Listing GCP folders", "parent", g.Parent)
	listReq := g.resourceManagerService.Folders.List()
	if g.Parent != "" {
		listReq = listReq.Parent(g.Parent)
	}
	err := listReq.Pages(context.Background(), func(page *cloudresourcemanager.ListFoldersResponse) error {
		for _, folder := range page.Folders {
			gcpFolder := &tab.CloudResource{
				Name:         folder.Name,
				DisplayName:  folder.DisplayName,
				Provider:     "gcp",
				ResourceType: "gcp_folder",
				Region:       "global",
				AccountRef:   folder.Name,
				Properties: map[string]any{
					"name":           folder.Name,
					"displayName":    folder.DisplayName,
					"parent":         folder.Parent,
					"lifecycleState": folder.LifecycleState,
					"createTime":     folder.CreateTime,
					"tags":           folder.Tags,
				},
			}
			slog.Debug("Found folder", "name", folder.Name, "displayName", folder.DisplayName, "parent", folder.Parent)
			g.Send(gcpFolder)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list folders: %w", err)
	}
	return nil
}
