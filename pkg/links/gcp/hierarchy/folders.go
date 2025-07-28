package hierarchy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/cloudresourcemanager/v1"
	cloudresourcemanagerv2 "google.golang.org/api/cloudresourcemanager/v2"
)

// FILE INFO:
// GcpFolderInfoLink - get info of a single folder, Process(folderName string)
// GcpFolderSubFolderListLink - list all folders in a folder, Process(resource tab.GCPResource); needs folder
// GcpFolderProjectListLink - list all projects in a folder, Process(resource tab.GCPResource); needs folder

type GcpFolderInfoLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanagerv2.Service
}

// creates a link to get info of a single folder
func NewGcpFolderInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpFolderInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFolderInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanagerv2.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager v2 service: %w", err)
	}
	return nil
}

func (g *GcpFolderInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpFolder(),
	)
	return params
}

func (g *GcpFolderInfoLink) Process(folderName string) error {
	folder, err := g.resourceManagerService.Folders.Get(folderName).Do()
	if err != nil {
		return fmt.Errorf("failed to get folder %s: %w", folderName, err)
	}
	gcpFolder, err := createGcpFolderResource(folder)
	if err != nil {
		return fmt.Errorf("failed to create GCP folder resource: %w", err)
	}
	g.Send(gcpFolder)
	return nil
}

type GcpFolderSubFolderListLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanagerv2.Service
}

// creates a link to list all folders in a folder
func NewGcpFolderSubFolderListLink(configs ...cfg.Config) chain.Link {
	g := &GcpFolderSubFolderListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFolderSubFolderListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanagerv2.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager v2 service: %w", err)
	}
	return nil
}

func (g *GcpFolderSubFolderListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceFolder {
		return nil
	}
	folderName := resource.Name
	listReq := g.resourceManagerService.Folders.List().Parent(folderName)
	err := listReq.Pages(context.Background(), func(page *cloudresourcemanagerv2.ListFoldersResponse) error {
		for _, folder := range page.Folders {
			gcpFolder, err := createGcpFolderResource(folder)
			if err != nil {
				slog.Error("Failed to create GCP folder resource", "error", err, "folder", folder.Name)
				continue
			}
			g.Send(gcpFolder)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list folders in folder %s: %w", folderName, err)
	}
	return nil
}

type GcpFolderProjectListLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
	FilterSysProjects      bool
}

// creates a link to list all projects in a folder
func NewGcpFolderProjectListLink(configs ...cfg.Config) chain.Link {
	g := &GcpFolderProjectListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFolderProjectListLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpFilterSysProjects(),
	)
	return params
}

func (g *GcpFolderProjectListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	filterSysProjects, err := cfg.As[bool](g.Arg("filter-sys-projects"))
	if err != nil {
		return fmt.Errorf("failed to get filter-sys-projects: %w", err)
	}
	g.FilterSysProjects = filterSysProjects
	return nil
}

func (g *GcpFolderProjectListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceFolder {
		return nil
	}
	folderName := resource.Name
	listReq := g.resourceManagerService.Projects.List().Filter(fmt.Sprintf("parent.id:%s", folderName))
	err := listReq.Pages(context.Background(), func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, project := range page.Projects {
			if g.FilterSysProjects && isSysProject(project) {
				continue
			}
			gcpProject, err := createGcpProjectResource(project)
			if err != nil {
				slog.Error("Failed to create GCP project resource", "error", err, "projectId", project.ProjectId)
				continue
			}
			g.Send(gcpProject)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list projects in folder %s: %w", folderName, err)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

func createGcpFolderResource(folder *cloudresourcemanagerv2.Folder) (*tab.GCPResource, error) {
	gcpFolder, err := tab.NewGCPResource(
		folder.Name,                   // resource name
		folder.Parent,                 // accountRef (hierarchy parent)
		tab.GCPResourceFolder,         // resource type
		linkPostProcessFolder(folder), // properties
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP folder resource: %w", err)
	}
	gcpFolder.DisplayName = folder.DisplayName
	return &gcpFolder, nil
}
