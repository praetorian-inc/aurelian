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

// GcpOrganizationLister lists all available organizations
type GcpOrganizationLister struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
}

func NewGcpOrganizationLister(configs ...cfg.Config) chain.Link {
	g := &GcpOrganizationLister{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrganizationLister) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return nil
}

func (g *GcpOrganizationLister) Process() error { // no resource input (meant to be non-contextual)
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
		properties := map[string]any{
			"displayName":    org.DisplayName,
			"name":           org.Name,
			"lifecycleState": org.LifecycleState,
			"creationTime":   org.CreationTime,
			"owner":          org.Owner,
		}
		gcpOrg, err := tab.NewGCPResource(
			org.Name,                    // resource name
			org.Name,                    // accountRef (self right now)
			tab.GCPResourceOrganization, // resource type
			properties,                  // properties
		)
		if err != nil {
			slog.Error("Failed to create GCP organization resource", "error", err, "org", org.Name)
			continue
		}
		g.Send(gcpOrg)
	}
	return nil
}

// GcpOrgInfoLink provides information about an organization resource
type GcpOrgInfoLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
}

func NewGcpOrgInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpOrgInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrgInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return nil
}

func (g *GcpOrgInfoLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceOrganization {
		slog.Debug("Skipping non-organization resource", "resourceType", resource.ResourceType)
		return nil
	}

	orgName := resource.Name
	slog.Debug("Getting organization info", "orgName", orgName)

	// Get fresh organization data
	org, err := g.resourceManagerService.Organizations.Get(orgName).Do()
	if err != nil {
		return fmt.Errorf("failed to get organization %s: %w", orgName, err)
	}

	// Send enriched organization info
	properties := map[string]any{
		"displayName":    org.DisplayName,
		"name":           org.Name,
		"lifecycleState": org.LifecycleState,
		"creationTime":   org.CreationTime,
		"owner":          org.Owner,
	}

	gcpOrg, err := tab.NewGCPResource(
		org.Name,                    // resource name
		org.Name,                    // accountRef (self right now)
		tab.GCPResourceOrganization, // resource type
		properties,                  // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP organization resource: %w", err)
	}

	g.Send(gcpOrg)
	return nil
}

// list folders within an organization
type GcpOrgFolderListLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
}

func NewGcpOrgFolderListLink(configs ...cfg.Config) chain.Link {
	g := &GcpOrgFolderListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrgFolderListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return nil
}

func (g *GcpOrgFolderListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceOrganization {
		slog.Debug("Skipping non-organization resource", "resourceType", resource.ResourceType)
		return nil
	}

	orgName := resource.Name
	slog.Debug("Listing folders in organization", "orgName", orgName)

	// We need to use v2 API for folders
	v2Service, err := cloudresourcemanagerv2.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create v2 resource manager service: %w", err)
	}

	listReq := v2Service.Folders.List().Parent(orgName)
	err = listReq.Pages(context.Background(), func(page *cloudresourcemanagerv2.ListFoldersResponse) error {
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
		return fmt.Errorf("failed to list folders in organization %s: %w", orgName, err)
	}
	return nil
}

// list projects within an organization
type GcpOrgProjectListLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
	FilterSysProjects      bool
}

func NewGcpOrgProjectListLink(configs ...cfg.Config) chain.Link {
	g := &GcpOrgProjectListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrgProjectListLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		cfg.NewParam[bool]("filter-sys-projects", "Filter out system projects like Apps Script projects").WithDefault(true),
	)
	return params
}

func (g *GcpOrgProjectListLink) Initialize() error {
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

func (g *GcpOrgProjectListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceOrganization {
		slog.Debug("Skipping non-organization resource", "resourceType", resource.ResourceType)
		return nil
	}

	orgName := resource.Name
	slog.Debug("Listing projects in organization", "orgName", orgName, "filterSysProjects", g.FilterSysProjects)

	// List projects with organization as parent
	listReq := g.resourceManagerService.Projects.List().Filter(fmt.Sprintf("parent.id:%s", orgName))
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
		return fmt.Errorf("failed to list projects in organization %s: %w", orgName, err)
	}
	return nil
}

// projects that should be filtered out
func (g *GcpOrgProjectListLink) isSysProject(project *cloudresourcemanager.Project) bool {
	// Same logic as in the original projects.go
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
