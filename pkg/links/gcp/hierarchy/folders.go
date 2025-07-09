package hierarchy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/cloudresourcemanager/v1"
	cloudresourcemanagerv2 "google.golang.org/api/cloudresourcemanager/v2"
)

// list folders within a folder
type GcpFolderListLink struct {
	*base.GcpBaseLink
	resourceManagerService   *cloudresourcemanager.Service
	resourceManagerServiceV2 *cloudresourcemanagerv2.Service
}

func NewGcpFolderListLink(configs ...cfg.Config) chain.Link {
	g := &GcpFolderListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFolderListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	g.resourceManagerServiceV2, err = cloudresourcemanagerv2.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager v2 service: %w", err)
	}
	return nil
}

func (g *GcpFolderListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceFolder {
		slog.Debug("Skipping non-folder resource", "resourceType", resource.ResourceType)
		return nil
	}
	folderName := resource.Name
	slog.Debug("Listing folders in folder", "folderName", folderName)
	listReq := g.resourceManagerServiceV2.Folders.List().Parent(folderName)
	err := listReq.Pages(context.Background(), func(page *cloudresourcemanagerv2.ListFoldersResponse) error {
		for _, folder := range page.Folders {
			properties := map[string]any{
				"name":           folder.Name,
				"displayName":    folder.DisplayName,
				"parent":         folder.Parent,
				"lifecycleState": folder.LifecycleState,
				"createTime":     folder.CreateTime,
				"tags":           folder.Tags,
			}
			gcpFolder, err := tab.NewGCPResource(
				folder.Name,           // resource name
				folder.Name,           // accountRef (folder is its own account ref)
				tab.GCPResourceFolder, // resource type
				properties,            // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP folder resource", "error", err, "folder", folder.Name)
				continue
			}
			slog.Debug("Found folder", "name", folder.Name, "displayName", folder.DisplayName, "parent", folder.Parent)
			g.Send(gcpFolder)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list folders in folder %s: %w", folderName, err)
	}
	return nil
}

// list projects within a folder
type GcpFolderProjectListLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
	FilterSysProjects      bool
}

func NewGcpFolderProjectListLink(configs ...cfg.Config) chain.Link {
	g := &GcpFolderProjectListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFolderProjectListLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		cfg.NewParam[bool]("filter-sys-projects", "Filter out system projects like Apps Script projects").WithDefault(true),
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
		slog.Debug("Skipping non-folder resource", "resourceType", resource.ResourceType)
		return nil
	}
	folderName := resource.Name
	slog.Debug("Listing projects in folder", "folderName", folderName, "filterSysProjects", g.FilterSysProjects)
	listReq := g.resourceManagerService.Projects.List().Filter(fmt.Sprintf("parent.id:%s", folderName))
	err := listReq.Pages(context.Background(), func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, project := range page.Projects {
			if g.FilterSysProjects && g.isSysProject(project) {
				slog.Debug("Skipping system project", "projectId", project.ProjectId, "name", project.Name)
				continue
			}
			properties := map[string]any{
				"projectId":      project.ProjectId,
				"name":           project.Name,
				"projectNumber":  project.ProjectNumber,
				"lifecycleState": project.LifecycleState,
				"createTime":     project.CreateTime,
				"parent":         project.Parent,
				"labels":         project.Labels,
			}
			gcpProject, err := tab.NewGCPResource(
				project.ProjectId,      // resource name
				project.ProjectId,      // accountRef (project is its own account ref)
				tab.GCPResourceProject, // resource type
				properties,             // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP project resource", "error", err, "projectId", project.ProjectId)
				continue
			}
			slog.Debug("Found project", "projectId", project.ProjectId, "name", project.Name, "state", project.LifecycleState)
			g.Send(gcpProject)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list projects in folder %s: %w", folderName, err)
	}
	return nil
}

// projects that should be filtered out
func (g *GcpFolderProjectListLink) isSysProject(project *cloudresourcemanager.Project) bool {
	sysPatterns := []string{
		"sys-",
		"script-editor-",
		"apps-script-",
		"system-",      // potentially worth removing
		"firebase-",    // potentially worth removing
		"cloud-build-", // potentially worth removing
		"gcf-",         // potentially worth removing
		"gae-",         // potentially worth removing
	}
	projectId := strings.ToLower(project.ProjectId)
	projectName := strings.ToLower(project.Name)
	for _, pattern := range sysPatterns {
		if strings.HasPrefix(projectId, pattern) || strings.HasPrefix(projectName, pattern) {
			return true
		}
	}
	return false
}
